// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! HTTP security headers for XSS, clickjacking, cache deception, and
//! cross-origin attack prevention.
//!
//! Provides pre-built header sets for four response categories: default
//! (strictest), API JSON, documentation HTML (nonce-based CSP), and internal
//! service-binding responses (no CORS). All sets enforce HSTS with preload,
//! `X-Frame-Options: DENY`, and `X-Content-Type-Options: nosniff`.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use worker::{Error as WorkerError, Response};

/// Generate a cryptographically secure CSP nonce for inline scripts.
///
/// # Returns
/// A base64-encoded random nonce suitable for CSP script-src directives.
///
/// # Security
/// Uses getrandom for cryptographically secure random bytes.
/// The nonce is 16 bytes (128 bits) encoded as base64.
pub fn generate_csp_nonce() -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let mut bytes = [0u8; 16];
    // SECURITY: If RNG fails, return a fixed nonce that will block all inline scripts
    // (CSP nonce mismatch). This is fail-safe: no scripts run rather than all scripts run.
    if getrandom::getrandom(&mut bytes).is_err() {
        return "AAAAAAAAAAAAAAAAAAAAAA==".to_string();
    }
    STANDARD.encode(bytes)
}

/// Security headers configuration.
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    headers: HashMap<String, String>,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        let mut headers = HashMap::new();

        // Prevent clickjacking.
        headers.insert("X-Frame-Options".to_string(), "DENY".to_string());

        // Prevent MIME type sniffing.
        headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());

        // Strict Content Security Policy with reporting directives (ASVS V3.4.7).
        headers.insert(
            "Content-Security-Policy".to_string(),
            "default-src 'none'; script-src 'none'; style-src 'none'; img-src 'none'; font-src 'none'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'none'; report-uri /v1/csp-report; report-to csp-endpoint; upgrade-insecure-requests".to_string()
        );

        // Report-To header for modern CSP reporting API (ASVS V3.4.7).
        headers.insert(
            "Report-To".to_string(),
            r#"{"group":"csp-endpoint","max_age":86400,"endpoints":[{"url":"/v1/csp-report"}]}"#
                .to_string(),
        );

        // Force HTTPS.
        headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000; includeSubDomains; preload".to_string(),
        );

        // Referrer policy: leak origin on same-protocol cross-origin navigations
        // for analytics, but strip path/query to protect sensitive URLs.
        headers.insert(
            "Referrer-Policy".to_string(),
            "strict-origin-when-cross-origin".to_string(),
        );

        // Permissions policy (formerly Feature Policy).
        // 27-feature list matching provii-issuer and provii-verifier.
        headers.insert(
            "Permissions-Policy".to_string(),
            "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), \
             camera=(), cross-origin-isolated=(), display-capture=(), \
             document-domain=(), encrypted-media=(), execution-while-not-rendered=(), \
             execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), \
             gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), \
             midi=(), navigation-override=(), payment=(), picture-in-picture=(), \
             publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), \
             usb=(), web-share=(), xr-spatial-tracking=()"
                .to_string(),
        );

        // Cache control for sensitive data.
        headers.insert(
            "Cache-Control".to_string(),
            "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0".to_string(),
        );

        // Prevent cross-domain policy files from being served.
        headers.insert(
            "X-Permitted-Cross-Domain-Policies".to_string(),
            "none".to_string(),
        );

        // Prevent cross-origin attacks via window references (ASVS V3.4.8).
        headers.insert(
            "Cross-Origin-Opener-Policy".to_string(),
            "same-origin".to_string(),
        );

        // Require explicit opt-in for cross-origin embedding.
        headers.insert(
            "Cross-Origin-Embedder-Policy".to_string(),
            "require-corp".to_string(),
        );

        // Restrict resource sharing to same-origin only.
        headers.insert(
            "Cross-Origin-Resource-Policy".to_string(),
            "same-origin".to_string(),
        );

        Self { headers }
    }
}

impl SecurityHeaders {
    /// Create security headers with a custom CSP.
    pub fn with_csp(csp: &str) -> Self {
        let mut headers = Self::default();
        headers
            .headers
            .insert("Content-Security-Policy".to_string(), csp.to_string());
        headers
    }

    /// Apply headers to a response.
    pub fn apply(&self, response: &mut Response) -> Result<(), WorkerError> {
        let response_headers = response.headers_mut();
        for (key, value) in &self.headers {
            response_headers.set(key, value)?;
        }
        Ok(())
    }
}

/// Add security headers to a response.
pub fn add_security_headers(mut response: Response) -> Result<Response, WorkerError> {
    let security_headers = SecurityHeaders::default();
    security_headers.apply(&mut response)?;

    // Add a request identifier for traceability.
    let request_id = uuid::Uuid::new_v4().to_string();
    response.headers_mut().set("X-Request-Id", &request_id)?;

    Ok(response)
}

/// Create security headers for API responses.
pub fn api_security_headers() -> SecurityHeaders {
    let mut headers = SecurityHeaders::default();

    // Relax the CSP for API endpoints that return JSON with reporting.
    headers.headers.insert(
        "Content-Security-Policy".to_string(),
        "default-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; report-uri /v1/csp-report; report-to csp-endpoint; upgrade-insecure-requests".to_string(),
    );

    // SECURITY: ASVS V14.2.5 - Cache deception prevention
    headers.headers.insert(
        "Cache-Control".to_string(),
        "no-store, no-cache, must-revalidate, private, max-age=0".to_string(),
    );
    headers
        .headers
        .insert("Pragma".to_string(), "no-cache".to_string());
    headers
        .headers
        .insert("Expires".to_string(), "0".to_string());

    headers
}

/// Create security headers for documentation endpoints (HTML content like Swagger UI).
///
/// # Arguments
/// * `nonce` - CSP nonce for inline scripts (should be generated per-request using `generate_csp_nonce()`)
///
/// # Security
/// Implements nonce-based CSP to avoid 'unsafe-inline' and 'unsafe-eval' (ASVS V2.2.3, V3.6.1)
pub fn docs_security_headers(nonce: &str) -> SecurityHeaders {
    let mut headers = SecurityHeaders::default();

    // Content-Type with charset
    headers.headers.insert(
        "Content-Type".to_string(),
        "text/html; charset=utf-8".to_string(),
    );

    // Nonce-based CSP for Swagger UI with reporting (ASVS V3.4.7) and SRI enforcement (ASVS V3.6.1)
    // Uses cryptographic nonce instead of 'unsafe-inline' and 'unsafe-eval'
    headers.headers.insert(
        "Content-Security-Policy".to_string(),
        format!(
            "default-src 'none'; \
             script-src 'nonce-{}' https://cdn.jsdelivr.net; \
             style-src 'nonce-{}' https://cdn.jsdelivr.net; \
             img-src 'self' data: https:; \
             connect-src 'self'; \
             font-src https://cdn.jsdelivr.net; \
             frame-ancestors 'none'; \
             base-uri 'none'; \
             object-src 'none'; \
             form-action 'none'; \
             require-sri-for script style; \
             report-uri /v1/csp-report; \
             report-to csp-endpoint; \
             upgrade-insecure-requests",
            nonce, nonce
        ),
    );

    // Public caching with revalidation (docs don't change frequently)
    headers.headers.insert(
        "Cache-Control".to_string(),
        "public, max-age=3600, must-revalidate".to_string(),
    );

    // Permissions policy (27-feature list, matching default headers)
    headers.headers.insert(
        "Permissions-Policy".to_string(),
        "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), \
         camera=(), cross-origin-isolated=(), display-capture=(), \
         document-domain=(), encrypted-media=(), execution-while-not-rendered=(), \
         execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), \
         gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), \
         midi=(), navigation-override=(), payment=(), picture-in-picture=(), \
         publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), \
         usb=(), web-share=(), xr-spatial-tracking=()"
            .to_string(),
    );

    // Prevent cross-origin attacks via window references (ASVS V3.4.8).
    headers.headers.insert(
        "Cross-Origin-Opener-Policy".to_string(),
        "same-origin".to_string(),
    );

    // Allow credentialless cross-origin embedding for CDN assets (Swagger UI).
    // Using 'credentialless' instead of 'require-corp' so that CDN resources
    // (jsDelivr) load without requiring Cross-Origin-Resource-Policy on the CDN.
    headers.headers.insert(
        "Cross-Origin-Embedder-Policy".to_string(),
        "credentialless".to_string(),
    );

    // Restrict resource sharing to same-origin only.
    headers.headers.insert(
        "Cross-Origin-Resource-Policy".to_string(),
        "same-origin".to_string(),
    );

    headers
}

/// Create security headers for internal service-binding endpoints.
///
/// # Security
/// Internal endpoints are called exclusively via Cloudflare service bindings (same-origin).
/// They MUST NOT include `Access-Control-*` CORS headers. CORS headers are only relevant
/// for browser cross-origin requests, and internal endpoints should be invisible to
/// browsers entirely. Including them would weaken the security boundary by signalling
/// that cross-origin access is expected.
///
/// Compared to [`api_security_headers`], this function:
/// - Omits all `Access-Control-*` headers
/// - Keeps all other security headers (HSTS, CSP, X-Frame-Options, etc.)
pub fn internal_security_headers() -> SecurityHeaders {
    let mut headers = SecurityHeaders::default();

    // Tighten CSP for internal API responses (JSON only, no UI).
    headers.headers.insert(
        "Content-Security-Policy".to_string(),
        "default-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; upgrade-insecure-requests".to_string(),
    );

    // SECURITY: ASVS V14.2.5 - Cache deception prevention
    headers.headers.insert(
        "Cache-Control".to_string(),
        "no-store, no-cache, must-revalidate, private, max-age=0".to_string(),
    );
    headers
        .headers
        .insert("Pragma".to_string(), "no-cache".to_string());
    headers
        .headers
        .insert("Expires".to_string(), "0".to_string());

    headers
}

/// Apply internal security headers to a response (no CORS headers).
///
/// This is the equivalent of `add_security_and_cors_headers` for internal routes,
/// but deliberately omits all `Access-Control-*` headers.
///
/// # Arguments
/// * `response` - The response to add headers to
///
/// # Returns
/// The response with security headers applied (no CORS).
pub fn add_internal_security_headers(mut response: Response) -> Result<Response, WorkerError> {
    let config = internal_security_headers();
    config.apply(&mut response)?;

    // Attach a request identifier for traceability.
    let request_id = uuid::Uuid::new_v4().to_string();
    response.headers_mut().set("X-Request-Id", &request_id)?;

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    SecurityHeaders DEFAULT TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_default_headers_count() {
        let headers = SecurityHeaders::default();
        // Should have 12 default headers (8 original + Report-To + 3 COOP/COEP/CORP)
        assert_eq!(headers.headers.len(), 12);
    }

    #[test]
    fn test_default_headers_x_frame_options() {
        let headers = SecurityHeaders::default();
        assert_eq!(
            headers.headers.get("X-Frame-Options"),
            Some(&"DENY".to_string())
        );
    }

    #[test]
    fn test_default_headers_x_content_type_options() {
        let headers = SecurityHeaders::default();
        assert_eq!(
            headers.headers.get("X-Content-Type-Options"),
            Some(&"nosniff".to_string())
        );
    }

    #[test]
    fn test_default_headers_no_xss_protection() {
        // CH-003: X-XSS-Protection removed (can introduce XSS in modern browsers)
        let headers = SecurityHeaders::default();
        assert!(!headers.headers.contains_key("X-XSS-Protection"));
    }

    #[test]
    fn test_default_headers_csp() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP header")?;
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        Ok(())
    }

    #[test]
    fn test_default_headers_hsts() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let hsts = headers
            .headers
            .get("Strict-Transport-Security")
            .ok_or("missing HSTS header")?;
        assert!(hsts.contains("max-age=31536000"));
        assert!(hsts.contains("includeSubDomains"));
        assert!(hsts.contains("preload"));
        Ok(())
    }

    #[test]
    fn test_default_headers_referrer_policy() {
        let headers = SecurityHeaders::default();
        assert_eq!(
            headers.headers.get("Referrer-Policy"),
            Some(&"strict-origin-when-cross-origin".to_string())
        );
    }

    #[test]
    fn test_default_headers_permissions_policy() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let policy = headers
            .headers
            .get("Permissions-Policy")
            .ok_or("missing Permissions-Policy header")?;
        assert!(policy.contains("camera=()"));
        assert!(policy.contains("microphone=()"));
        assert!(policy.contains("geolocation=()"));
        Ok(())
    }

    #[test]
    fn test_default_headers_cache_control() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let cache = headers
            .headers
            .get("Cache-Control")
            .ok_or("missing Cache-Control header")?;
        assert!(cache.contains("no-store"));
        assert!(cache.contains("no-cache"));
        assert!(cache.contains("must-revalidate"));
        Ok(())
    }

    #[test]
    fn test_default_headers_cross_domain_policies() {
        let headers = SecurityHeaders::default();
        assert_eq!(
            headers.headers.get("X-Permitted-Cross-Domain-Policies"),
            Some(&"none".to_string())
        );
    }

    #[test]
    fn test_default_headers_coop() {
        let headers = SecurityHeaders::default();
        assert_eq!(
            headers.headers.get("Cross-Origin-Opener-Policy"),
            Some(&"same-origin".to_string())
        );
    }

    #[test]
    fn test_default_headers_coep() {
        let headers = SecurityHeaders::default();
        assert_eq!(
            headers.headers.get("Cross-Origin-Embedder-Policy"),
            Some(&"require-corp".to_string())
        );
    }

    #[test]
    fn test_default_headers_corp() {
        let headers = SecurityHeaders::default();
        assert_eq!(
            headers.headers.get("Cross-Origin-Resource-Policy"),
            Some(&"same-origin".to_string())
        );
    }

    /* ========================================================================== */
    /*                    with_csp() TESTS                                       */
    /* ========================================================================== */

    #[test]
    fn test_with_csp_custom() {
        let custom_csp = "default-src 'self'; script-src 'self'";
        let headers = SecurityHeaders::with_csp(custom_csp);

        assert_eq!(
            headers.headers.get("Content-Security-Policy"),
            Some(&custom_csp.to_string())
        );
    }

    #[test]
    fn test_with_csp_preserves_other_headers() {
        let headers = SecurityHeaders::with_csp("custom-policy");

        // Other headers should still be present
        assert!(headers.headers.contains_key("X-Frame-Options"));
        assert!(headers.headers.contains_key("Strict-Transport-Security"));
        assert_eq!(headers.headers.len(), 12); // 8 base + Report-To + 3 COOP/COEP/CORP
    }

    #[test]
    fn test_with_csp_empty_string() {
        let headers = SecurityHeaders::with_csp("");
        assert_eq!(
            headers.headers.get("Content-Security-Policy"),
            Some(&String::new())
        );
    }

    /* ========================================================================== */
    /*                    api_security_headers() TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_api_security_headers_relaxed_csp() -> Result<(), Box<dyn std::error::Error>> {
        let headers = api_security_headers();
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP header")?;

        // Updated to match implementation with CSP reporting directives (ASVS V3.4.7)
        assert_eq!(csp, "default-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; report-uri /v1/csp-report; report-to csp-endpoint; upgrade-insecure-requests");
        Ok(())
    }

    #[test]
    fn test_api_security_headers_cache_control() -> Result<(), Box<dyn std::error::Error>> {
        let headers = api_security_headers();
        let cache = headers
            .headers
            .get("Cache-Control")
            .ok_or("missing Cache-Control header")?;

        // Updated to match implementation with cache deception prevention (ASVS V14.2.5)
        assert_eq!(
            cache,
            "no-store, no-cache, must-revalidate, private, max-age=0"
        );
        Ok(())
    }

    #[test]
    fn test_api_security_headers_has_core_security() {
        let headers = api_security_headers();

        // Should still have core security headers
        assert!(headers.headers.contains_key("X-Frame-Options"));
        assert!(headers.headers.contains_key("X-Content-Type-Options"));
        assert!(headers.headers.contains_key("Strict-Transport-Security"));
    }

    /* ========================================================================== */
    /*                    DEBUG AND CLONE TESTS                                  */
    /* ========================================================================== */

    #[test]
    fn test_security_headers_debug() {
        let headers = SecurityHeaders::default();
        let debug_str = format!("{:?}", headers);
        assert!(debug_str.contains("SecurityHeaders"));
        assert!(debug_str.contains("headers"));
    }

    #[test]
    fn test_security_headers_clone() {
        let headers1 = SecurityHeaders::default();
        let headers2 = headers1.clone();

        assert_eq!(headers1.headers.len(), headers2.headers.len());
        for (key, value) in &headers1.headers {
            assert_eq!(headers2.headers.get(key), Some(value));
        }
    }

    /* ========================================================================== */
    /*                    SECURITY PROPERTY TESTS                                */
    /* ========================================================================== */

    #[test]
    fn test_hsts_includes_subdomain() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let hsts = headers
            .headers
            .get("Strict-Transport-Security")
            .ok_or("missing HSTS header")?;
        assert!(hsts.contains("includeSubDomains"));
        Ok(())
    }

    #[test]
    fn test_csp_prevents_inline_scripts() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP header")?;
        // Should not allow 'unsafe-inline'
        assert!(!csp.contains("unsafe-inline"));
        Ok(())
    }

    #[test]
    fn test_csp_prevents_eval() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP header")?;
        // Should not allow 'unsafe-eval'
        assert!(!csp.contains("unsafe-eval"));
        Ok(())
    }

    #[test]
    fn test_referrer_policy_no_downgrade() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let referrer = headers
            .headers
            .get("Referrer-Policy")
            .ok_or("missing Referrer-Policy header")?;
        // Should not downgrade to insecure referrer
        assert!(!referrer.contains("unsafe-url"));
        assert!(!referrer.contains("no-referrer-when-downgrade"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    HEADER COMPLETENESS TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_all_critical_headers_present() {
        let headers = SecurityHeaders::default();
        let critical_headers = vec![
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
        ];

        for header in critical_headers {
            assert!(
                headers.headers.contains_key(header),
                "Missing critical header: {}",
                header
            );
        }
    }

    #[test]
    fn test_no_empty_header_values() {
        let headers = SecurityHeaders::default();

        for (key, value) in &headers.headers {
            assert!(!value.is_empty(), "Header {} has empty value", key);
        }
    }

    #[test]
    fn test_no_duplicate_keys() {
        let headers = SecurityHeaders::default();

        // HashMap ensures no duplicate keys by design, but verify count
        let expected_count = 12; // 8 original + Report-To + 3 COOP/COEP/CORP
        assert_eq!(headers.headers.len(), expected_count);
    }

    /* ========================================================================== */
    /*                    COMPARISON TESTS                                       */
    /* ========================================================================== */

    #[test]
    fn test_default_vs_api_headers_differences() {
        let default_headers = SecurityHeaders::default();
        let api_headers = api_security_headers();

        // CSP should be different
        assert_ne!(
            default_headers.headers.get("Content-Security-Policy"),
            api_headers.headers.get("Content-Security-Policy")
        );

        // Cache-Control should be different
        assert_ne!(
            default_headers.headers.get("Cache-Control"),
            api_headers.headers.get("Cache-Control")
        );
    }

    #[test]
    fn test_api_headers_more_permissive_than_default() -> Result<(), Box<dyn std::error::Error>> {
        let default_headers = SecurityHeaders::default();
        let api_headers = api_security_headers();

        let default_csp = default_headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing default CSP header")?;
        let api_csp = api_headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing API CSP header")?;

        // API CSP should be shorter (more permissive)
        assert!(api_csp.len() < default_csp.len());
        Ok(())
    }

    /* ========================================================================== */
    /*                    internal_security_headers() TESTS                      */
    /* ========================================================================== */

    #[test]
    fn test_internal_headers_no_cors() {
        let headers = internal_security_headers();
        // SECURITY (SB-009): Internal endpoints MUST NOT have CORS headers
        assert!(
            !headers.headers.contains_key("Access-Control-Allow-Origin"),
            "Internal headers must not include Access-Control-Allow-Origin"
        );
        assert!(
            !headers.headers.contains_key("Access-Control-Allow-Methods"),
            "Internal headers must not include Access-Control-Allow-Methods"
        );
        assert!(
            !headers.headers.contains_key("Access-Control-Allow-Headers"),
            "Internal headers must not include Access-Control-Allow-Headers"
        );
        assert!(
            !headers
                .headers
                .contains_key("Access-Control-Allow-Credentials"),
            "Internal headers must not include Access-Control-Allow-Credentials"
        );
        assert!(
            !headers.headers.contains_key("Access-Control-Max-Age"),
            "Internal headers must not include Access-Control-Max-Age"
        );
    }

    #[test]
    fn test_internal_headers_has_core_security() {
        let headers = internal_security_headers();
        assert!(headers.headers.contains_key("X-Frame-Options"));
        assert!(headers.headers.contains_key("X-Content-Type-Options"));
        assert!(headers.headers.contains_key("Strict-Transport-Security"));
        assert!(headers.headers.contains_key("Content-Security-Policy"));
        assert!(headers.headers.contains_key("Referrer-Policy"));
    }

    #[test]
    fn test_internal_headers_cache_control() -> Result<(), Box<dyn std::error::Error>> {
        let headers = internal_security_headers();
        let cache = headers
            .headers
            .get("Cache-Control")
            .ok_or("missing Cache-Control header")?;
        assert!(cache.contains("no-store"));
        assert!(cache.contains("private"));
        Ok(())
    }

    #[test]
    fn test_internal_headers_csp_strict() -> Result<(), Box<dyn std::error::Error>> {
        let headers = internal_security_headers();
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP header")?;
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("upgrade-insecure-requests"));
        // Internal CSP should NOT include report-uri (no external reporting)
        assert!(!csp.contains("report-uri"));
        Ok(())
    }

    #[test]
    fn test_internal_headers_no_vary_origin() {
        let headers = internal_security_headers();
        // Internal headers should not have Vary: Origin since there are no CORS headers
        assert!(
            !headers
                .headers
                .get("Vary")
                .is_some_and(|v| v.contains("Origin")),
            "Internal headers should not Vary on Origin"
        );
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: with_csp always sets the CSP header
        #[test]
        fn prop_with_csp_sets_header(csp in "[a-zA-Z0-9 ;'()-]{10,100}") {
            let headers = SecurityHeaders::with_csp(&csp);
            prop_assert_eq!(
                headers.headers.get("Content-Security-Policy"),
                Some(&csp)
            );
        }

        /// Property: with_csp maintains all other headers
        #[test]
        fn prop_with_csp_preserves_header_count(csp in ".*") {
            let default_count = SecurityHeaders::default().headers.len();
            let custom_headers = SecurityHeaders::with_csp(&csp);

            prop_assert_eq!(custom_headers.headers.len(), default_count);
        }

        /// Property: Default headers are consistent across instantiations
        #[test]
        fn prop_default_headers_consistent(_seed in any::<u8>()) {
            let headers1 = SecurityHeaders::default();
            let headers2 = SecurityHeaders::default();

            prop_assert_eq!(headers1.headers.len(), headers2.headers.len());

            for (key, value) in &headers1.headers {
                prop_assert_eq!(headers2.headers.get(key), Some(value));
            }
        }

        /// Property: All header values are non-empty strings
        #[test]
        fn prop_no_empty_values(_seed in any::<u8>()) {
            let all_headers = vec![
                SecurityHeaders::default(),
                api_security_headers(),
                internal_security_headers(),
            ];

            for headers in all_headers {
                for (key, value) in &headers.headers {
                    prop_assert!(!value.is_empty(), "Header {} has empty value", key);
                }
            }
        }

        /// Property: Clone produces identical headers
        #[test]
        fn prop_clone_identical(_seed in any::<u8>()) {
            let original = SecurityHeaders::default();
            let cloned = original.clone();

            prop_assert_eq!(original.headers.len(), cloned.headers.len());

            for (key, value) in &original.headers {
                prop_assert_eq!(cloned.headers.get(key), Some(value));
            }
        }

        /// Property: API headers always have CSP
        #[test]
        fn prop_api_headers_have_csp(_seed in any::<u8>()) {
            let headers = api_security_headers();
            prop_assert!(headers.headers.contains_key("Content-Security-Policy"));
        }

        /// Property: Default headers prevent caching
        #[test]
        fn prop_default_prevents_caching(_seed in any::<u8>()) {
            let headers = SecurityHeaders::default();
            let cache = headers.headers.get("Cache-Control")
                .ok_or(proptest::test_runner::TestCaseError::fail("missing Cache-Control header"))?;

            prop_assert!(cache.contains("no-store") || cache.contains("no-cache"));
        }

        /// Property: HSTS is always present and strong
        #[test]
        fn prop_hsts_always_strong(_seed in any::<u8>()) {
            let all_headers = vec![
                SecurityHeaders::default(),
                api_security_headers(),
                internal_security_headers(),
            ];

            for headers in all_headers {
                let hsts = headers.headers.get("Strict-Transport-Security")
                    .ok_or(proptest::test_runner::TestCaseError::fail("missing HSTS header"))?;
                prop_assert!(hsts.contains("max-age="));
                prop_assert!(hsts.contains("31536000")); // 1 year minimum
            }
        }

        /// Property: X-Frame-Options always denies
        #[test]
        fn prop_frame_options_deny(_seed in any::<u8>()) {
            let all_headers = vec![
                SecurityHeaders::default(),
                api_security_headers(),
                internal_security_headers(),
            ];

            for headers in all_headers {
                let frame = headers.headers.get("X-Frame-Options")
                    .ok_or(proptest::test_runner::TestCaseError::fail("missing X-Frame-Options header"))?;
                prop_assert_eq!(frame, "DENY");
            }
        }

        /// Property: Internal headers never have CORS headers
        #[test]
        fn prop_internal_no_cors(_seed in any::<u8>()) {
            let headers = internal_security_headers();
            for key in headers.headers.keys() {
                prop_assert!(
                    !key.starts_with("Access-Control"),
                    "Internal headers must not contain CORS header: {}",
                    key
                );
            }
        }
    }

    /* ========================================================================== */
    /*                    docs_security_headers() TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_docs_headers_csp_contains_nonce() -> Result<(), Box<dyn std::error::Error>> {
        let nonce = "dGVzdG5vbmNl";
        let headers = docs_security_headers(nonce);
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP header")?;
        assert!(csp.contains(&format!("'nonce-{}'", nonce)));
        Ok(())
    }

    #[test]
    fn test_docs_headers_csp_nonce_appears_twice() -> Result<(), Box<dyn std::error::Error>> {
        let nonce = "abc123";
        let headers = docs_security_headers(nonce);
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP header")?;
        // Nonce should appear in both script-src and style-src.
        let count = csp.matches(&format!("'nonce-{}'", nonce)).count();
        assert_eq!(count, 2, "nonce should appear in script-src and style-src");
        Ok(())
    }

    #[test]
    fn test_docs_headers_content_type_html() -> Result<(), Box<dyn std::error::Error>> {
        let headers = docs_security_headers("nonce");
        let ct = headers
            .headers
            .get("Content-Type")
            .ok_or("missing Content-Type")?;
        assert_eq!(ct, "text/html; charset=utf-8");
        Ok(())
    }

    #[test]
    fn test_docs_headers_cache_control_public() -> Result<(), Box<dyn std::error::Error>> {
        let headers = docs_security_headers("nonce");
        let cache = headers
            .headers
            .get("Cache-Control")
            .ok_or("missing Cache-Control")?;
        assert!(cache.contains("public"));
        assert!(cache.contains("max-age=3600"));
        assert!(cache.contains("must-revalidate"));
        Ok(())
    }

    #[test]
    fn test_docs_headers_coep_credentialless() {
        let headers = docs_security_headers("nonce");
        assert_eq!(
            headers.headers.get("Cross-Origin-Embedder-Policy"),
            Some(&"credentialless".to_string())
        );
    }

    #[test]
    fn test_docs_headers_coop_same_origin() {
        let headers = docs_security_headers("nonce");
        assert_eq!(
            headers.headers.get("Cross-Origin-Opener-Policy"),
            Some(&"same-origin".to_string())
        );
    }

    #[test]
    fn test_docs_headers_corp_same_origin() {
        let headers = docs_security_headers("nonce");
        assert_eq!(
            headers.headers.get("Cross-Origin-Resource-Policy"),
            Some(&"same-origin".to_string())
        );
    }

    #[test]
    fn test_docs_headers_has_permissions_policy() -> Result<(), Box<dyn std::error::Error>> {
        let headers = docs_security_headers("nonce");
        let policy = headers
            .headers
            .get("Permissions-Policy")
            .ok_or("missing Permissions-Policy")?;
        assert!(policy.contains("camera=()"));
        assert!(policy.contains("microphone=()"));
        Ok(())
    }

    #[test]
    fn test_docs_headers_csp_has_cdn_sources() -> Result<(), Box<dyn std::error::Error>> {
        let headers = docs_security_headers("nonce");
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP")?;
        assert!(csp.contains("https://cdn.jsdelivr.net"));
        Ok(())
    }

    #[test]
    fn test_docs_headers_csp_has_sri_enforcement() -> Result<(), Box<dyn std::error::Error>> {
        let headers = docs_security_headers("nonce");
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP")?;
        assert!(csp.contains("require-sri-for script style"));
        Ok(())
    }

    #[test]
    fn test_docs_headers_csp_has_reporting() -> Result<(), Box<dyn std::error::Error>> {
        let headers = docs_security_headers("nonce");
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP")?;
        assert!(csp.contains("report-uri /v1/csp-report"));
        assert!(csp.contains("report-to csp-endpoint"));
        Ok(())
    }

    #[test]
    fn test_docs_headers_no_unsafe_inline() -> Result<(), Box<dyn std::error::Error>> {
        let headers = docs_security_headers("nonce");
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP")?;
        assert!(!csp.contains("unsafe-inline"));
        assert!(!csp.contains("unsafe-eval"));
        Ok(())
    }

    #[test]
    fn test_docs_headers_has_frame_ancestors_none() -> Result<(), Box<dyn std::error::Error>> {
        let headers = docs_security_headers("nonce");
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP")?;
        assert!(csp.contains("frame-ancestors 'none'"));
        Ok(())
    }

    #[test]
    fn test_docs_headers_has_hsts() {
        let headers = docs_security_headers("nonce");
        assert!(headers.headers.contains_key("Strict-Transport-Security"));
    }

    #[test]
    fn test_docs_headers_has_x_frame_options() {
        let headers = docs_security_headers("nonce");
        assert_eq!(
            headers.headers.get("X-Frame-Options"),
            Some(&"DENY".to_string())
        );
    }

    /* ========================================================================== */
    /*                    generate_csp_nonce() TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_csp_nonce_is_base64() {
        let nonce = generate_csp_nonce();
        // Base64 encoding of 16 bytes = 24 characters (with padding).
        assert_eq!(nonce.len(), 24);
        assert!(
            nonce.ends_with("==")
                || nonce.ends_with('=')
                || nonce
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        );
    }

    #[test]
    fn test_csp_nonce_uniqueness() {
        let nonce1 = generate_csp_nonce();
        let nonce2 = generate_csp_nonce();
        // Two sequential nonces from a CSPRNG should differ.
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_csp_nonce_not_empty() {
        let nonce = generate_csp_nonce();
        assert!(!nonce.is_empty());
    }

    /* ========================================================================== */
    /*                    api_security_headers() ADDITIONAL TESTS                */
    /* ========================================================================== */

    #[test]
    fn test_api_headers_has_pragma_no_cache() {
        let headers = api_security_headers();
        assert_eq!(headers.headers.get("Pragma"), Some(&"no-cache".to_string()));
    }

    #[test]
    fn test_api_headers_has_expires_zero() {
        let headers = api_security_headers();
        assert_eq!(headers.headers.get("Expires"), Some(&"0".to_string()));
    }

    #[test]
    fn test_api_headers_csp_has_reporting() -> Result<(), Box<dyn std::error::Error>> {
        let headers = api_security_headers();
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP")?;
        assert!(csp.contains("report-uri /v1/csp-report"));
        assert!(csp.contains("report-to csp-endpoint"));
        Ok(())
    }

    #[test]
    fn test_api_headers_csp_has_upgrade_insecure() -> Result<(), Box<dyn std::error::Error>> {
        let headers = api_security_headers();
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP")?;
        assert!(csp.contains("upgrade-insecure-requests"));
        Ok(())
    }

    #[test]
    fn test_api_headers_has_report_to() {
        let headers = api_security_headers();
        assert!(headers.headers.contains_key("Report-To"));
    }

    /* ========================================================================== */
    /*                    internal_security_headers() ADDITIONAL TESTS           */
    /* ========================================================================== */

    #[test]
    fn test_internal_headers_has_pragma_no_cache() {
        let headers = internal_security_headers();
        assert_eq!(headers.headers.get("Pragma"), Some(&"no-cache".to_string()));
    }

    #[test]
    fn test_internal_headers_has_expires_zero() {
        let headers = internal_security_headers();
        assert_eq!(headers.headers.get("Expires"), Some(&"0".to_string()));
    }

    #[test]
    fn test_internal_headers_has_permissions_policy() {
        let headers = internal_security_headers();
        assert!(headers.headers.contains_key("Permissions-Policy"));
    }

    #[test]
    fn test_internal_headers_has_cross_domain_policies() {
        let headers = internal_security_headers();
        assert_eq!(
            headers.headers.get("X-Permitted-Cross-Domain-Policies"),
            Some(&"none".to_string())
        );
    }

    #[test]
    fn test_internal_headers_coop_same_origin() {
        let headers = internal_security_headers();
        assert_eq!(
            headers.headers.get("Cross-Origin-Opener-Policy"),
            Some(&"same-origin".to_string())
        );
    }

    #[test]
    fn test_internal_headers_coep_require_corp() {
        let headers = internal_security_headers();
        assert_eq!(
            headers.headers.get("Cross-Origin-Embedder-Policy"),
            Some(&"require-corp".to_string())
        );
    }

    #[test]
    fn test_internal_headers_corp_same_origin() {
        let headers = internal_security_headers();
        assert_eq!(
            headers.headers.get("Cross-Origin-Resource-Policy"),
            Some(&"same-origin".to_string())
        );
    }

    /* ========================================================================== */
    /*                    CROSS-VARIANT CONSISTENCY TESTS                        */
    /* ========================================================================== */

    #[test]
    fn test_all_variants_have_hsts() {
        let variants: Vec<SecurityHeaders> = vec![
            SecurityHeaders::default(),
            api_security_headers(),
            internal_security_headers(),
            docs_security_headers("nonce"),
        ];
        for (i, h) in variants.iter().enumerate() {
            assert!(
                h.headers.contains_key("Strict-Transport-Security"),
                "variant {} missing HSTS",
                i
            );
        }
    }

    #[test]
    fn test_all_variants_have_x_frame_options_deny() {
        let variants: Vec<SecurityHeaders> = vec![
            SecurityHeaders::default(),
            api_security_headers(),
            internal_security_headers(),
            docs_security_headers("nonce"),
        ];
        for (i, h) in variants.iter().enumerate() {
            assert_eq!(
                h.headers.get("X-Frame-Options"),
                Some(&"DENY".to_string()),
                "variant {} has wrong X-Frame-Options",
                i
            );
        }
    }

    #[test]
    fn test_all_variants_have_nosniff() {
        let variants: Vec<SecurityHeaders> = vec![
            SecurityHeaders::default(),
            api_security_headers(),
            internal_security_headers(),
            docs_security_headers("nonce"),
        ];
        for (i, h) in variants.iter().enumerate() {
            assert_eq!(
                h.headers.get("X-Content-Type-Options"),
                Some(&"nosniff".to_string()),
                "variant {} missing nosniff",
                i
            );
        }
    }

    #[test]
    fn test_all_variants_have_csp() {
        let variants: Vec<SecurityHeaders> = vec![
            SecurityHeaders::default(),
            api_security_headers(),
            internal_security_headers(),
            docs_security_headers("nonce"),
        ];
        for (i, h) in variants.iter().enumerate() {
            assert!(
                h.headers.contains_key("Content-Security-Policy"),
                "variant {} missing CSP",
                i
            );
        }
    }

    #[test]
    fn test_all_variants_have_referrer_policy() {
        let variants: Vec<SecurityHeaders> = vec![
            SecurityHeaders::default(),
            api_security_headers(),
            internal_security_headers(),
            docs_security_headers("nonce"),
        ];
        for (i, h) in variants.iter().enumerate() {
            assert!(
                h.headers.contains_key("Referrer-Policy"),
                "variant {} missing Referrer-Policy",
                i
            );
        }
    }

    #[test]
    fn test_no_variant_has_xss_protection() {
        let variants: Vec<SecurityHeaders> = vec![
            SecurityHeaders::default(),
            api_security_headers(),
            internal_security_headers(),
            docs_security_headers("nonce"),
        ];
        for (i, h) in variants.iter().enumerate() {
            assert!(
                !h.headers.contains_key("X-XSS-Protection"),
                "variant {} should not have X-XSS-Protection",
                i
            );
        }
    }

    /* ========================================================================== */
    /*                    DEFAULT CSP DIRECTIVE DETAIL TESTS                     */
    /* ========================================================================== */

    #[test]
    fn test_default_csp_has_all_directives() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP")?;
        assert!(csp.contains("script-src 'none'"));
        assert!(csp.contains("style-src 'none'"));
        assert!(csp.contains("img-src 'none'"));
        assert!(csp.contains("font-src 'none'"));
        assert!(csp.contains("connect-src 'self'"));
        assert!(csp.contains("base-uri 'none'"));
        assert!(csp.contains("object-src 'none'"));
        assert!(csp.contains("form-action 'none'"));
        assert!(csp.contains("upgrade-insecure-requests"));
        Ok(())
    }

    #[test]
    fn test_default_csp_has_reporting() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let csp = headers
            .headers
            .get("Content-Security-Policy")
            .ok_or("missing CSP")?;
        assert!(csp.contains("report-uri /v1/csp-report"));
        assert!(csp.contains("report-to csp-endpoint"));
        Ok(())
    }

    #[test]
    fn test_default_report_to_header_is_json() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let report_to = headers
            .headers
            .get("Report-To")
            .ok_or("missing Report-To")?;
        let parsed: serde_json::Value = serde_json::from_str(report_to)?;
        assert_eq!(parsed["group"], "csp-endpoint");
        assert_eq!(parsed["max_age"], 86400);
        Ok(())
    }

    /* ========================================================================== */
    /*                    PERMISSIONS POLICY FEATURE COUNT TESTS                 */
    /* ========================================================================== */

    #[test]
    fn test_default_permissions_policy_has_27_features() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let policy = headers
            .headers
            .get("Permissions-Policy")
            .ok_or("missing Permissions-Policy")?;
        // Each feature is in the form `feature=()`. Count the `=()` occurrences.
        let count = policy.matches("=()").count();
        assert_eq!(count, 27, "Expected 27 disabled features, got {}", count);
        Ok(())
    }

    #[test]
    fn test_docs_permissions_policy_has_27_features() -> Result<(), Box<dyn std::error::Error>> {
        let headers = docs_security_headers("nonce");
        let policy = headers
            .headers
            .get("Permissions-Policy")
            .ok_or("missing Permissions-Policy")?;
        let count = policy.matches("=()").count();
        assert_eq!(count, 27, "Expected 27 disabled features, got {}", count);
        Ok(())
    }

    /* ========================================================================== */
    /*                    HSTS MAX-AGE VALUE TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_hsts_max_age_is_one_year() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let hsts = headers
            .headers
            .get("Strict-Transport-Security")
            .ok_or("missing HSTS")?;
        // 31536000 = 365 * 24 * 60 * 60
        assert!(hsts.contains("max-age=31536000"));
        Ok(())
    }

    #[test]
    fn test_hsts_has_preload() -> Result<(), Box<dyn std::error::Error>> {
        let headers = SecurityHeaders::default();
        let hsts = headers
            .headers
            .get("Strict-Transport-Security")
            .ok_or("missing HSTS")?;
        assert!(hsts.contains("preload"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    docs vs default DIFF TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_docs_overrides_cache_control_from_default() {
        let default_headers = SecurityHeaders::default();
        let docs_headers = docs_security_headers("nonce");
        // Default is no-store, docs is public caching.
        assert_ne!(
            default_headers.headers.get("Cache-Control"),
            docs_headers.headers.get("Cache-Control")
        );
    }

    #[test]
    fn test_docs_overrides_coep_from_default() {
        let default_headers = SecurityHeaders::default();
        let docs_headers = docs_security_headers("nonce");
        // Default is require-corp, docs is credentialless.
        assert_ne!(
            default_headers.headers.get("Cross-Origin-Embedder-Policy"),
            docs_headers.headers.get("Cross-Origin-Embedder-Policy")
        );
    }

    #[test]
    fn test_docs_has_content_type_but_default_does_not() {
        let default_headers = SecurityHeaders::default();
        let docs_headers = docs_security_headers("nonce");
        assert!(!default_headers.headers.contains_key("Content-Type"));
        assert!(docs_headers.headers.contains_key("Content-Type"));
    }
}
