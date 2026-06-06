// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Security headers middleware for the hosted verification flow.
//!
//! Applies a hardened set of HTTP response headers to every response, including
//! error responses. The header set covers MIME sniffing prevention, clickjacking
//! protection, HSTS, CSP, cross-origin isolation (COOP/COEP/CORP), a 21-feature
//! Permissions-Policy deny list, and cache control per ASVS 14.2.2/14.3.2.
//!
//! SECURITY: All profiles (Production, Development, Custom) apply identical
//! strict CSP. No profile permits `unsafe-eval` or `unsafe-inline`. Version
//! headers are intentionally omitted (EIL-027) to prevent service fingerprinting.

use worker::Response;

/// Security headers configuration profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Strict production security headers.
    Production,
    /// Development headers (same strict CSP as production; HSTS disabled).
    Development,
    /// Custom profile with caller-specified settings.
    Custom,
}

/// Cache control policy for responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheControlPolicy {
    /// No caching, for authenticated or sensitive endpoints (session tokens, CSRF).
    NoCache,
    /// Public caching with short TTL (e.g. 60s for JWKS).
    PublicShortTtl(u32),
    /// Public caching with medium TTL (e.g. 300s for health checks).
    PublicMediumTtl(u32),
    /// Public caching with long TTL plus `immutable` (e.g. 3600s for static).
    PublicLongTtl(u32),
    /// Caller-specified Cache-Control value.
    Custom(String),
}

/// Security headers configuration.
#[derive(Debug, Clone)]
pub struct SecurityHeadersConfig {
    /// Active security profile.
    pub profile: SecurityProfile,

    /// Enable HSTS (Strict-Transport-Security).
    pub enable_hsts: bool,

    /// HSTS max-age in seconds (default: 31 536 000 = 1 year).
    pub hsts_max_age: u32,

    /// Include subdomains in HSTS.
    pub hsts_include_subdomains: bool,

    /// HSTS preload flag.
    pub hsts_preload: bool,

    /// Enable Content-Security-Policy header.
    pub enable_csp: bool,

    /// Custom CSP policy string (overrides the profile default when set).
    pub csp_policy: Option<String>,

    /// SECURITY: Cache control policy. Defaults to `NoCache` so session tokens
    /// and sensitive data are never cached by browsers or proxies.
    pub cache_control_policy: CacheControlPolicy,

    /// API version (internal use only; never sent in response headers per EIL-027).
    pub api_version: Option<String>,

    /// Worker version (internal use only; never sent in response headers per EIL-027).
    pub worker_version: Option<String>,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self::production()
    }
}

impl SecurityHeadersConfig {
    /// Production security headers (strict). HSTS enabled with 1-year max-age.
    pub fn production() -> Self {
        Self {
            profile: SecurityProfile::Production,
            enable_hsts: true,
            hsts_max_age: 31_536_000, // 1 year
            hsts_include_subdomains: true,
            hsts_preload: true,
            enable_csp: true,
            csp_policy: None, // Use default production CSP
            cache_control_policy: CacheControlPolicy::NoCache, // Strict no-cache by default
            api_version: Some("1.0.0".to_string()),
            worker_version: Some("1.0.0".to_string()),
        }
    }

    /// Development headers. Same strict CSP as production; HSTS disabled.
    pub fn development() -> Self {
        Self {
            profile: SecurityProfile::Development,
            enable_hsts: false,
            hsts_max_age: 0,
            hsts_include_subdomains: false,
            hsts_preload: false,
            enable_csp: true,
            csp_policy: None, // Use default development CSP
            cache_control_policy: CacheControlPolicy::NoCache, // Still no-cache for dev
            api_version: Some("1.0.0-dev".to_string()),
            worker_version: Some("1.0.0-dev".to_string()),
        }
    }

    /// Blank-slate config. CSP and HSTS both disabled; caller sets as needed.
    pub fn custom() -> Self {
        Self {
            profile: SecurityProfile::Custom,
            enable_hsts: false,
            hsts_max_age: 0,
            hsts_include_subdomains: false,
            hsts_preload: false,
            enable_csp: false,
            csp_policy: None,
            cache_control_policy: CacheControlPolicy::NoCache,
            api_version: None,
            worker_version: None,
        }
    }

    /// Set API version (internal use only; not exposed in response headers).
    pub fn with_api_version(mut self, version: String) -> Self {
        self.api_version = Some(version);
        self
    }

    /// Set worker version (internal use only; not exposed in response headers).
    pub fn with_worker_version(mut self, version: String) -> Self {
        self.worker_version = Some(version);
        self
    }

    /// Override the profile-default CSP with a custom policy string.
    pub fn with_csp_policy(mut self, policy: String) -> Self {
        self.csp_policy = Some(policy);
        self
    }

    /// Set the cache control policy.
    pub fn with_cache_control(mut self, policy: CacheControlPolicy) -> Self {
        self.cache_control_policy = policy;
        self
    }
}

/// Apply the full security header set to `response`.
///
/// SECURITY: Always-on headers (X-Content-Type-Options, X-Frame-Options,
/// Referrer-Policy, 21-feature Permissions-Policy, COOP, COEP, CORP) are
/// applied unconditionally. HSTS and CSP are gated by their respective config
/// flags. Cache-Control is set last via [`add_cache_control_headers`].
///
/// Applied to every response, including error responses.
pub fn add_security_headers(
    response: &mut Response,
    config: &SecurityHeadersConfig,
) -> Result<(), worker::Error> {
    {
        let headers = response.headers_mut();

        // SECURITY: Always-on headers applied unconditionally.

        headers.set("X-Content-Type-Options", "nosniff")?;
        headers.set("X-Frame-Options", "DENY")?;

        // CH-029: X-XSS-Protection intentionally omitted. Deprecated in modern
        // browsers; can introduce XSS via filter abuse. CSP provides protection.

        headers.set("Referrer-Policy", "no-referrer")?;

        // Restrict dangerous browser features (21-feature list, matching provii-issuer/provii-verifier).
        // Deprecated/non-standard features removed: ambient-light-sensor, battery,
        // document-domain, execution-while-not-rendered, execution-while-out-of-viewport,
        // navigation-override.
        headers.set(
            "Permissions-Policy",
            "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), \
             display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), \
             gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), \
             midi=(), payment=(), picture-in-picture=(), \
             publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), \
             usb=(), web-share=(), xr-spatial-tracking=()",
        )?;

        // SECURITY: Cross-origin isolation (COOP/COEP/CORP, ASVS V3.4.8).
        headers.set("Cross-Origin-Opener-Policy", "same-origin")?;
        headers.set("Cross-Origin-Embedder-Policy", "require-corp")?;
        headers.set("Cross-Origin-Resource-Policy", "same-origin")?;

        // SECURITY: HSTS (Strict-Transport-Security).
        if config.enable_hsts {
            let mut hsts_value = format!("max-age={}", config.hsts_max_age);

            if config.hsts_include_subdomains {
                hsts_value.push_str("; includeSubDomains");
            }

            if config.hsts_preload {
                hsts_value.push_str("; preload");
            }

            headers.set("Strict-Transport-Security", &hsts_value)?;
        }

        // SECURITY: Content-Security-Policy.
        if config.enable_csp {
            let csp_policy = if let Some(custom_policy) = &config.csp_policy {
                custom_policy.clone()
            } else {
                // Default CSP based on profile
                match config.profile {
                    SecurityProfile::Production => {
                        // Strict API-only CSP: this backend serves JSON, not HTML.
                        // Matches provii-issuer and provii-verifier CSP policy.
                        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests"
                            .to_string()
                    }
                    SecurityProfile::Development => {
                        // CH-028: Development uses the same strict CSP as production.
                        // No unsafe-eval or unsafe-inline allowed in any profile.
                        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests"
                            .to_string()
                    }
                    SecurityProfile::Custom => {
                        // CH-030: Custom profile uses strict CSP matching production
                        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests"
                            .to_string()
                    }
                }
            };

            headers.set("Content-Security-Policy", &csp_policy)?;
        }

        // SECURITY: EIL-027 -- version headers intentionally omitted to prevent
        // service fingerprinting.
    } // headers borrow dropped here

    add_cache_control_headers(response, &config.cache_control_policy)?;

    Ok(())
}

/// Set cache-control headers on `response` per `policy`.
///
/// SECURITY: `NoCache` emits `no-store, no-cache, must-revalidate, private,
/// max-age=0` plus HTTP/1.0 `Pragma` and `Expires` for belt-and-braces
/// prevention of session token caching (ASVS 14.2.2/14.3.2). Session tokens and
/// authentication endpoints MUST use `NoCache`. Public endpoints (health, JWKS)
/// may use a public TTL variant.
pub fn add_cache_control_headers(
    response: &mut Response,
    policy: &CacheControlPolicy,
) -> Result<(), worker::Error> {
    let headers = response.headers_mut();

    match policy {
        CacheControlPolicy::NoCache => {
            // SECURITY: No caching for sensitive endpoints (ASVS 14.2.2, 14.3.2).
            headers.set(
                "Cache-Control",
                "no-store, no-cache, must-revalidate, private, max-age=0",
            )?;
            headers.set("Pragma", "no-cache")?; // HTTP/1.0 compatibility
            headers.set("Expires", "0")?; // HTTP/1.0 compatibility
        }
        CacheControlPolicy::PublicShortTtl(ttl) => {
            // Public caching with short TTL (e.g., JWKS, health checks)
            headers.set("Cache-Control", &format!("public, max-age={}", ttl))?;
        }
        CacheControlPolicy::PublicMediumTtl(ttl) => {
            // Public caching with medium TTL
            headers.set("Cache-Control", &format!("public, max-age={}", ttl))?;
        }
        CacheControlPolicy::PublicLongTtl(ttl) => {
            // Public caching with long TTL (e.g., static resources)
            headers.set(
                "Cache-Control",
                &format!("public, max-age={}, immutable", ttl),
            )?;
        }
        CacheControlPolicy::Custom(value) => {
            // Custom cache control value
            headers.set("Cache-Control", value)?;
        }
    }

    Ok(())
}

/// Best-effort security header application for middleware error responses.
///
/// Header-setting failures are silently discarded since the response is
/// already an error. Used by CORS, request validation, Sec-Fetch, and body
/// size limit middleware.
pub fn apply_security_headers_best_effort(response: &mut Response) {
    let config = SecurityHeadersConfig::production();
    let _ = add_security_headers(response, &config);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_config() {
        let config = SecurityHeadersConfig::production();
        assert_eq!(config.profile, SecurityProfile::Production);
        assert!(config.enable_hsts);
        assert_eq!(config.hsts_max_age, 31_536_000);
        assert!(config.hsts_include_subdomains);
        assert!(config.hsts_preload);
        assert!(config.enable_csp);
    }

    #[test]
    fn test_development_config() {
        let config = SecurityHeadersConfig::development();
        assert_eq!(config.profile, SecurityProfile::Development);
        assert!(!config.enable_hsts);
        assert!(config.enable_csp);
    }

    #[test]
    fn test_custom_config() {
        let config = SecurityHeadersConfig::custom()
            .with_api_version("2.0.0".to_string())
            .with_worker_version("2.0.0".to_string());

        assert_eq!(config.profile, SecurityProfile::Custom);
        assert_eq!(config.api_version, Some("2.0.0".to_string()));
        assert_eq!(config.worker_version, Some("2.0.0".to_string()));
    }

    #[test]
    fn test_with_csp_policy() {
        let custom_csp = "default-src 'none'";
        let config = SecurityHeadersConfig::custom().with_csp_policy(custom_csp.to_string());

        assert_eq!(config.csp_policy, Some(custom_csp.to_string()));
    }

    #[test]
    fn test_cache_control_policy_no_cache() {
        let config = SecurityHeadersConfig::production();
        assert_eq!(config.cache_control_policy, CacheControlPolicy::NoCache);
    }

    #[test]
    fn test_cache_control_policy_public_short_ttl() {
        let config = SecurityHeadersConfig::production()
            .with_cache_control(CacheControlPolicy::PublicShortTtl(60));
        assert_eq!(
            config.cache_control_policy,
            CacheControlPolicy::PublicShortTtl(60)
        );
    }

    #[test]
    fn test_cache_control_policy_public_medium_ttl() {
        let config = SecurityHeadersConfig::production()
            .with_cache_control(CacheControlPolicy::PublicMediumTtl(300));
        assert_eq!(
            config.cache_control_policy,
            CacheControlPolicy::PublicMediumTtl(300)
        );
    }

    #[test]
    fn test_cache_control_policy_public_long_ttl() {
        let config = SecurityHeadersConfig::production()
            .with_cache_control(CacheControlPolicy::PublicLongTtl(3600));
        assert_eq!(
            config.cache_control_policy,
            CacheControlPolicy::PublicLongTtl(3600)
        );
    }

    #[test]
    fn test_cache_control_policy_custom() {
        let custom_value = "private, max-age=120";
        let config = SecurityHeadersConfig::production()
            .with_cache_control(CacheControlPolicy::Custom(custom_value.to_string()));
        assert_eq!(
            config.cache_control_policy,
            CacheControlPolicy::Custom(custom_value.to_string())
        );
    }

    // ── Default config is production ────────────────────────────────────

    #[test]
    fn test_default_is_production() {
        let config = SecurityHeadersConfig::default();
        assert_eq!(config.profile, SecurityProfile::Production);
        assert!(config.enable_hsts);
        assert!(config.enable_csp);
    }

    // ── Builder chaining ────────────────────────────────────────────────

    #[test]
    fn test_builder_chain_all_methods() {
        let config = SecurityHeadersConfig::custom()
            .with_api_version("3.0.0".to_string())
            .with_worker_version("3.0.0".to_string())
            .with_csp_policy("default-src 'self'".to_string())
            .with_cache_control(CacheControlPolicy::PublicShortTtl(120));

        assert_eq!(config.api_version, Some("3.0.0".to_string()));
        assert_eq!(config.worker_version, Some("3.0.0".to_string()));
        assert_eq!(config.csp_policy, Some("default-src 'self'".to_string()));
        assert_eq!(
            config.cache_control_policy,
            CacheControlPolicy::PublicShortTtl(120)
        );
    }

    // ── Custom config defaults ──────────────────────────────────────────

    #[test]
    fn test_custom_config_defaults() {
        let config = SecurityHeadersConfig::custom();
        assert_eq!(config.profile, SecurityProfile::Custom);
        assert!(!config.enable_hsts);
        assert!(!config.enable_csp);
        assert_eq!(config.hsts_max_age, 0);
        assert!(!config.hsts_include_subdomains);
        assert!(!config.hsts_preload);
        assert_eq!(config.api_version, None);
        assert_eq!(config.worker_version, None);
        assert_eq!(config.csp_policy, None);
    }

    // ── Development config details ──────────────────────────────────────

    #[test]
    fn test_development_config_details() {
        let config = SecurityHeadersConfig::development();
        assert_eq!(config.hsts_max_age, 0);
        assert!(!config.hsts_include_subdomains);
        assert!(!config.hsts_preload);
        assert_eq!(config.api_version, Some("1.0.0-dev".to_string()));
        assert_eq!(config.worker_version, Some("1.0.0-dev".to_string()));
    }

    // ── Production HSTS details ─────────────────────────────────────────

    #[test]
    fn test_production_hsts_one_year() {
        let config = SecurityHeadersConfig::production();
        assert_eq!(config.hsts_max_age, 31_536_000);
    }

    // ── SecurityProfile equality ────────────────────────────────────────

    #[test]
    fn test_security_profile_equality() {
        assert_eq!(SecurityProfile::Production, SecurityProfile::Production);
        assert_eq!(SecurityProfile::Development, SecurityProfile::Development);
        assert_eq!(SecurityProfile::Custom, SecurityProfile::Custom);
        assert_ne!(SecurityProfile::Production, SecurityProfile::Development);
        assert_ne!(SecurityProfile::Production, SecurityProfile::Custom);
        assert_ne!(SecurityProfile::Development, SecurityProfile::Custom);
    }

    // ── CacheControlPolicy equality ─────────────────────────────────────

    #[test]
    fn test_cache_control_policy_equality() {
        assert_eq!(CacheControlPolicy::NoCache, CacheControlPolicy::NoCache);
        assert_ne!(
            CacheControlPolicy::NoCache,
            CacheControlPolicy::PublicShortTtl(60)
        );
        assert_ne!(
            CacheControlPolicy::PublicShortTtl(60),
            CacheControlPolicy::PublicShortTtl(120)
        );
        assert_ne!(
            CacheControlPolicy::PublicShortTtl(60),
            CacheControlPolicy::PublicMediumTtl(60)
        );
    }

    // ── add_security_headers to a real Response ─────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_security_headers_production() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production();
        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let h = resp.headers();
        assert_eq!(
            h.get("X-Content-Type-Options").ok().flatten().as_deref(),
            Some("nosniff")
        );
        assert_eq!(
            h.get("X-Frame-Options").ok().flatten().as_deref(),
            Some("DENY")
        );
        assert_eq!(
            h.get("Referrer-Policy").ok().flatten().as_deref(),
            Some("no-referrer")
        );
        assert_eq!(
            h.get("Cross-Origin-Opener-Policy")
                .ok()
                .flatten()
                .as_deref(),
            Some("same-origin")
        );
        assert_eq!(
            h.get("Cross-Origin-Embedder-Policy")
                .ok()
                .flatten()
                .as_deref(),
            Some("require-corp")
        );
        assert_eq!(
            h.get("Cross-Origin-Resource-Policy")
                .ok()
                .flatten()
                .as_deref(),
            Some("same-origin")
        );
        // HSTS should be present in production
        let hsts = h
            .get("Strict-Transport-Security")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert!(hsts.contains("max-age=31536000"));
        assert!(hsts.contains("includeSubDomains"));
        assert!(hsts.contains("preload"));
        // CSP should be present
        let csp = h
            .get("Content-Security-Policy")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        // Cache-Control should be no-store (NoCache default)
        let cc = h.get("Cache-Control").ok().flatten().unwrap_or_default();
        assert!(cc.contains("no-store"));
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_security_headers_development_no_hsts() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::development();
        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let h = resp.headers();
        // Development should NOT have HSTS
        assert!(h.get("Strict-Transport-Security").ok().flatten().is_none());
        // But CSP should still be present
        assert!(h.get("Content-Security-Policy").ok().flatten().is_some());
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_security_headers_custom_no_csp_no_hsts() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::custom();
        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let h = resp.headers();
        assert!(h.get("Strict-Transport-Security").ok().flatten().is_none());
        assert!(h.get("Content-Security-Policy").ok().flatten().is_none());
        // Always-on headers should still be present
        assert_eq!(
            h.get("X-Content-Type-Options").ok().flatten().as_deref(),
            Some("nosniff")
        );
        assert_eq!(
            h.get("X-Frame-Options").ok().flatten().as_deref(),
            Some("DENY")
        );
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_security_headers_custom_csp() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production()
            .with_csp_policy("default-src 'self'; script-src 'none'".to_string());
        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let csp = resp
            .headers()
            .get("Content-Security-Policy")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(csp, "default-src 'self'; script-src 'none'");
        Ok(())
    }

    // ── add_cache_control_headers variants ──────────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_cache_control_no_cache() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(200);
        add_cache_control_headers(&mut resp, &CacheControlPolicy::NoCache)?;

        let h = resp.headers();
        let cc = h.get("Cache-Control").ok().flatten().unwrap_or_default();
        assert!(cc.contains("no-store"));
        assert!(cc.contains("no-cache"));
        assert!(cc.contains("must-revalidate"));
        assert!(cc.contains("private"));
        assert!(cc.contains("max-age=0"));
        assert_eq!(h.get("Pragma").ok().flatten().as_deref(), Some("no-cache"));
        assert_eq!(h.get("Expires").ok().flatten().as_deref(), Some("0"));
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_cache_control_public_short_ttl() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(200);
        add_cache_control_headers(&mut resp, &CacheControlPolicy::PublicShortTtl(60))?;

        let cc = resp
            .headers()
            .get("Cache-Control")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(cc, "public, max-age=60");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_cache_control_public_medium_ttl() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(200);
        add_cache_control_headers(&mut resp, &CacheControlPolicy::PublicMediumTtl(300))?;

        let cc = resp
            .headers()
            .get("Cache-Control")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(cc, "public, max-age=300");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_cache_control_public_long_ttl_immutable() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut resp = worker::Response::empty()?.with_status(200);
        add_cache_control_headers(&mut resp, &CacheControlPolicy::PublicLongTtl(3600))?;

        let cc = resp
            .headers()
            .get("Cache-Control")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(cc, "public, max-age=3600, immutable");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_cache_control_custom() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(200);
        add_cache_control_headers(
            &mut resp,
            &CacheControlPolicy::Custom("private, max-age=120".to_string()),
        )?;

        let cc = resp
            .headers()
            .get("Cache-Control")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(cc, "private, max-age=120");
        Ok(())
    }

    // ── apply_security_headers_best_effort ───────────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_apply_security_headers_best_effort() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(500);
        apply_security_headers_best_effort(&mut resp);

        let h = resp.headers();
        // Should apply production headers even on error responses
        assert_eq!(
            h.get("X-Content-Type-Options").ok().flatten().as_deref(),
            Some("nosniff")
        );
        assert_eq!(
            h.get("X-Frame-Options").ok().flatten().as_deref(),
            Some("DENY")
        );
        Ok(())
    }

    // ── Permissions-Policy is present ───────────────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_permissions_policy_present() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production();
        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let pp = resp
            .headers()
            .get("Permissions-Policy")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert!(pp.contains("camera=()"));
        assert!(pp.contains("microphone=()"));
        assert!(pp.contains("geolocation=()"));
        assert!(pp.contains("payment=()"));
        Ok(())
    }

    // ── EIL-027: no version headers in output ───────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_no_version_headers_emitted() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production();
        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let h = resp.headers();
        assert!(h.get("X-API-Version").ok().flatten().is_none());
        assert!(h.get("X-Worker-Version").ok().flatten().is_none());
        assert!(h.get("Server").ok().flatten().is_none());
        Ok(())
    }

    // ── Debug and Clone trait coverage ─────────────────────────────────

    #[test]
    fn test_security_profile_debug() {
        let debug_str = format!("{:?}", SecurityProfile::Production);
        assert_eq!(debug_str, "Production");
        let debug_str = format!("{:?}", SecurityProfile::Development);
        assert_eq!(debug_str, "Development");
        let debug_str = format!("{:?}", SecurityProfile::Custom);
        assert_eq!(debug_str, "Custom");
    }

    #[test]
    fn test_security_profile_clone() {
        let original = SecurityProfile::Production;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_cache_control_policy_debug() {
        let debug_str = format!("{:?}", CacheControlPolicy::NoCache);
        assert!(debug_str.contains("NoCache"));
        let debug_str = format!("{:?}", CacheControlPolicy::PublicShortTtl(60));
        assert!(debug_str.contains("60"));
        let debug_str = format!("{:?}", CacheControlPolicy::PublicMediumTtl(300));
        assert!(debug_str.contains("300"));
        let debug_str = format!("{:?}", CacheControlPolicy::PublicLongTtl(3600));
        assert!(debug_str.contains("3600"));
        let debug_str = format!("{:?}", CacheControlPolicy::Custom("x".to_string()));
        assert!(debug_str.contains("x"));
    }

    #[test]
    fn test_cache_control_policy_clone() {
        let original = CacheControlPolicy::PublicShortTtl(42);
        let cloned = original.clone();
        assert_eq!(original, cloned);

        let original = CacheControlPolicy::Custom("test-value".to_string());
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_security_headers_config_debug() {
        let config = SecurityHeadersConfig::production();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("Production"));
        assert!(debug_str.contains("enable_hsts: true"));
    }

    #[test]
    fn test_security_headers_config_clone() {
        let config = SecurityHeadersConfig::production()
            .with_api_version("1.2.3".to_string())
            .with_csp_policy("custom".to_string());
        let cloned = config.clone();
        assert_eq!(cloned.profile, SecurityProfile::Production);
        assert_eq!(cloned.api_version, Some("1.2.3".to_string()));
        assert_eq!(cloned.csp_policy, Some("custom".to_string()));
        assert_eq!(cloned.enable_hsts, config.enable_hsts);
        assert_eq!(cloned.hsts_max_age, config.hsts_max_age);
    }

    // ── HSTS partial combinations ──────────────────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_hsts_max_age_only() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = SecurityHeadersConfig::production();
        config.hsts_include_subdomains = false;
        config.hsts_preload = false;

        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let hsts = resp
            .headers()
            .get("Strict-Transport-Security")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(hsts, "max-age=31536000");
        assert!(!hsts.contains("includeSubDomains"));
        assert!(!hsts.contains("preload"));
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_hsts_with_subdomains_no_preload() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = SecurityHeadersConfig::production();
        config.hsts_include_subdomains = true;
        config.hsts_preload = false;

        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let hsts = resp
            .headers()
            .get("Strict-Transport-Security")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(hsts, "max-age=31536000; includeSubDomains");
        assert!(!hsts.contains("preload"));
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_hsts_with_preload_no_subdomains() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = SecurityHeadersConfig::production();
        config.hsts_include_subdomains = false;
        config.hsts_preload = true;

        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let hsts = resp
            .headers()
            .get("Strict-Transport-Security")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(hsts, "max-age=31536000; preload");
        assert!(!hsts.contains("includeSubDomains"));
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_hsts_custom_max_age() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = SecurityHeadersConfig::production();
        config.hsts_max_age = 86400; // 1 day
        config.hsts_include_subdomains = false;
        config.hsts_preload = false;

        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let hsts = resp
            .headers()
            .get("Strict-Transport-Security")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(hsts, "max-age=86400");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_hsts_zero_max_age() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = SecurityHeadersConfig::production();
        config.hsts_max_age = 0;
        config.hsts_include_subdomains = true;
        config.hsts_preload = true;

        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let hsts = resp
            .headers()
            .get("Strict-Transport-Security")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(hsts, "max-age=0; includeSubDomains; preload");
        Ok(())
    }

    // ── CSP profile default branches ───────────────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_csp_default_development_profile() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::development();
        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let csp = resp
            .headers()
            .get("Content-Security-Policy")
            .ok()
            .flatten()
            .unwrap_or_default();
        // CH-028: Development uses same strict CSP as production
        assert_eq!(
            csp,
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests"
        );
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_csp_default_custom_profile() -> Result<(), Box<dyn std::error::Error>> {
        // Custom profile with CSP enabled but no custom policy string
        let mut config = SecurityHeadersConfig::custom();
        config.enable_csp = true;

        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let csp = resp
            .headers()
            .get("Content-Security-Policy")
            .ok()
            .flatten()
            .unwrap_or_default();
        // CH-030: Custom profile falls through to strict CSP
        assert_eq!(
            csp,
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests"
        );
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_csp_custom_policy_overrides_profile_default() -> Result<(), Box<dyn std::error::Error>>
    {
        let custom_csp = "default-src 'self'; img-src *";
        let config = SecurityHeadersConfig::development().with_csp_policy(custom_csp.to_string());

        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let csp = resp
            .headers()
            .get("Content-Security-Policy")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(csp, custom_csp);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_csp_disabled_no_header() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = SecurityHeadersConfig::production();
        config.enable_csp = false;

        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        assert!(resp
            .headers()
            .get("Content-Security-Policy")
            .ok()
            .flatten()
            .is_none());
        Ok(())
    }

    // ── Cross-origin headers on all profiles ───────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_cross_origin_headers_on_development() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::development();
        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let h = resp.headers();
        assert_eq!(
            h.get("Cross-Origin-Opener-Policy")
                .ok()
                .flatten()
                .as_deref(),
            Some("same-origin")
        );
        assert_eq!(
            h.get("Cross-Origin-Embedder-Policy")
                .ok()
                .flatten()
                .as_deref(),
            Some("require-corp")
        );
        assert_eq!(
            h.get("Cross-Origin-Resource-Policy")
                .ok()
                .flatten()
                .as_deref(),
            Some("same-origin")
        );
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_cross_origin_headers_on_custom() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::custom();
        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let h = resp.headers();
        assert_eq!(
            h.get("Cross-Origin-Opener-Policy")
                .ok()
                .flatten()
                .as_deref(),
            Some("same-origin")
        );
        assert_eq!(
            h.get("Cross-Origin-Embedder-Policy")
                .ok()
                .flatten()
                .as_deref(),
            Some("require-corp")
        );
        assert_eq!(
            h.get("Cross-Origin-Resource-Policy")
                .ok()
                .flatten()
                .as_deref(),
            Some("same-origin")
        );
        Ok(())
    }

    // ── Permissions-Policy full 21-feature list ────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_permissions_policy_all_21_features() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production();
        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let pp = resp
            .headers()
            .get("Permissions-Policy")
            .ok()
            .flatten()
            .unwrap_or_default();

        let expected_features = [
            "accelerometer=()",
            "autoplay=()",
            "camera=()",
            "cross-origin-isolated=()",
            "display-capture=()",
            "encrypted-media=()",
            "fullscreen=()",
            "geolocation=()",
            "gyroscope=()",
            "keyboard-map=()",
            "magnetometer=()",
            "microphone=()",
            "midi=()",
            "payment=()",
            "picture-in-picture=()",
            "publickey-credentials-get=()",
            "screen-wake-lock=()",
            "sync-xhr=()",
            "usb=()",
            "web-share=()",
            "xr-spatial-tracking=()",
        ];

        for feature in &expected_features {
            assert!(
                pp.contains(feature),
                "Permissions-Policy missing feature: {}",
                feature
            );
        }

        // Verify exactly 21 features (count comma-separated segments)
        let feature_count = pp.split(',').count();
        assert_eq!(
            feature_count, 21,
            "Expected 21 features in Permissions-Policy"
        );
        Ok(())
    }

    // ── Deprecated features NOT present ────────────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_permissions_policy_no_deprecated_features() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production();
        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let pp = resp
            .headers()
            .get("Permissions-Policy")
            .ok()
            .flatten()
            .unwrap_or_default();

        let deprecated_features = [
            "ambient-light-sensor",
            "battery",
            "document-domain",
            "execution-while-not-rendered",
            "execution-while-out-of-viewport",
            "navigation-override",
        ];

        for feature in &deprecated_features {
            assert!(
                !pp.contains(feature),
                "Permissions-Policy should NOT contain deprecated feature: {}",
                feature
            );
        }
        Ok(())
    }

    // ── X-XSS-Protection intentionally omitted (CH-029) ───────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_no_x_xss_protection_header() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production();
        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        assert!(
            resp.headers()
                .get("X-XSS-Protection")
                .ok()
                .flatten()
                .is_none(),
            "X-XSS-Protection should be omitted (CH-029)"
        );
        Ok(())
    }

    // ── Cache control TTL boundary values ──────────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_cache_control_short_ttl_zero() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(200);
        add_cache_control_headers(&mut resp, &CacheControlPolicy::PublicShortTtl(0))?;

        let cc = resp
            .headers()
            .get("Cache-Control")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(cc, "public, max-age=0");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_cache_control_medium_ttl_zero() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(200);
        add_cache_control_headers(&mut resp, &CacheControlPolicy::PublicMediumTtl(0))?;

        let cc = resp
            .headers()
            .get("Cache-Control")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(cc, "public, max-age=0");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_cache_control_long_ttl_zero() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(200);
        add_cache_control_headers(&mut resp, &CacheControlPolicy::PublicLongTtl(0))?;

        let cc = resp
            .headers()
            .get("Cache-Control")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(cc, "public, max-age=0, immutable");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_cache_control_short_ttl_max_u32() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(200);
        add_cache_control_headers(&mut resp, &CacheControlPolicy::PublicShortTtl(u32::MAX))?;

        let cc = resp
            .headers()
            .get("Cache-Control")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(cc, format!("public, max-age={}", u32::MAX));
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_cache_control_long_ttl_max_u32() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(200);
        add_cache_control_headers(&mut resp, &CacheControlPolicy::PublicLongTtl(u32::MAX))?;

        let cc = resp
            .headers()
            .get("Cache-Control")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(cc, format!("public, max-age={}, immutable", u32::MAX));
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_cache_control_custom_empty_string() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(200);
        add_cache_control_headers(&mut resp, &CacheControlPolicy::Custom(String::new()))?;

        let cc = resp
            .headers()
            .get("Cache-Control")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(cc, "");
        Ok(())
    }

    // ── Builder method overwrites ──────────────────────────────────────

    #[test]
    fn test_builder_cache_control_overwrite() {
        let config = SecurityHeadersConfig::production()
            .with_cache_control(CacheControlPolicy::PublicShortTtl(60))
            .with_cache_control(CacheControlPolicy::PublicLongTtl(7200));

        assert_eq!(
            config.cache_control_policy,
            CacheControlPolicy::PublicLongTtl(7200)
        );
    }

    #[test]
    fn test_builder_api_version_overwrite() {
        let config = SecurityHeadersConfig::production()
            .with_api_version("1.0.0".to_string())
            .with_api_version("2.0.0".to_string());

        assert_eq!(config.api_version, Some("2.0.0".to_string()));
    }

    #[test]
    fn test_builder_worker_version_overwrite() {
        let config = SecurityHeadersConfig::production()
            .with_worker_version("1.0.0".to_string())
            .with_worker_version("2.0.0".to_string());

        assert_eq!(config.worker_version, Some("2.0.0".to_string()));
    }

    #[test]
    fn test_builder_csp_policy_overwrite() {
        let config = SecurityHeadersConfig::production()
            .with_csp_policy("first".to_string())
            .with_csp_policy("second".to_string());

        assert_eq!(config.csp_policy, Some("second".to_string()));
    }

    // ── Production field-level completeness ────────────────────────────

    #[test]
    fn test_production_config_all_fields() {
        let config = SecurityHeadersConfig::production();
        assert_eq!(config.profile, SecurityProfile::Production);
        assert!(config.enable_hsts);
        assert_eq!(config.hsts_max_age, 31_536_000);
        assert!(config.hsts_include_subdomains);
        assert!(config.hsts_preload);
        assert!(config.enable_csp);
        assert_eq!(config.csp_policy, None);
        assert_eq!(config.cache_control_policy, CacheControlPolicy::NoCache);
        assert_eq!(config.api_version, Some("1.0.0".to_string()));
        assert_eq!(config.worker_version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_development_config_all_fields() {
        let config = SecurityHeadersConfig::development();
        assert_eq!(config.profile, SecurityProfile::Development);
        assert!(!config.enable_hsts);
        assert_eq!(config.hsts_max_age, 0);
        assert!(!config.hsts_include_subdomains);
        assert!(!config.hsts_preload);
        assert!(config.enable_csp);
        assert_eq!(config.csp_policy, None);
        assert_eq!(config.cache_control_policy, CacheControlPolicy::NoCache);
        assert_eq!(config.api_version, Some("1.0.0-dev".to_string()));
        assert_eq!(config.worker_version, Some("1.0.0-dev".to_string()));
    }

    #[test]
    fn test_custom_config_all_fields() {
        let config = SecurityHeadersConfig::custom();
        assert_eq!(config.profile, SecurityProfile::Custom);
        assert!(!config.enable_hsts);
        assert_eq!(config.hsts_max_age, 0);
        assert!(!config.hsts_include_subdomains);
        assert!(!config.hsts_preload);
        assert!(!config.enable_csp);
        assert_eq!(config.csp_policy, None);
        assert_eq!(config.cache_control_policy, CacheControlPolicy::NoCache);
        assert_eq!(config.api_version, None);
        assert_eq!(config.worker_version, None);
    }

    // ── apply_security_headers_best_effort full verification ───────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_best_effort_applies_hsts() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(503);
        apply_security_headers_best_effort(&mut resp);

        let hsts = resp
            .headers()
            .get("Strict-Transport-Security")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert!(
            hsts.contains("max-age=31536000"),
            "Best-effort should apply production HSTS"
        );
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_best_effort_applies_csp() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(403);
        apply_security_headers_best_effort(&mut resp);

        let csp = resp
            .headers()
            .get("Content-Security-Policy")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert!(
            csp.contains("default-src 'none'"),
            "Best-effort should apply production CSP"
        );
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_best_effort_applies_cache_control() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(500);
        apply_security_headers_best_effort(&mut resp);

        let cc = resp
            .headers()
            .get("Cache-Control")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert!(
            cc.contains("no-store"),
            "Best-effort should apply NoCache cache control"
        );
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_best_effort_applies_referrer_policy() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(500);
        apply_security_headers_best_effort(&mut resp);

        assert_eq!(
            resp.headers()
                .get("Referrer-Policy")
                .ok()
                .flatten()
                .as_deref(),
            Some("no-referrer")
        );
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_best_effort_applies_permissions_policy() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(500);
        apply_security_headers_best_effort(&mut resp);

        let pp = resp
            .headers()
            .get("Permissions-Policy")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert!(
            pp.contains("camera=()"),
            "Best-effort should apply Permissions-Policy"
        );
        Ok(())
    }

    // ── add_security_headers with various cache policies ───────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_full_headers_with_public_short_ttl() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production()
            .with_cache_control(CacheControlPolicy::PublicShortTtl(60));

        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let h = resp.headers();
        // Security headers still present
        assert_eq!(
            h.get("X-Content-Type-Options").ok().flatten().as_deref(),
            Some("nosniff")
        );
        // Cache control matches the policy
        let cc = h.get("Cache-Control").ok().flatten().unwrap_or_default();
        assert_eq!(cc, "public, max-age=60");
        // Pragma and Expires should NOT be set for public caching
        assert!(h.get("Pragma").ok().flatten().is_none());
        assert!(h.get("Expires").ok().flatten().is_none());
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_full_headers_with_custom_cache() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production()
            .with_cache_control(CacheControlPolicy::Custom("no-transform".to_string()));

        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let cc = resp
            .headers()
            .get("Cache-Control")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(cc, "no-transform");
        Ok(())
    }

    // ── HSTS disabled means no header ──────────────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_hsts_disabled_explicitly() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = SecurityHeadersConfig::production();
        config.enable_hsts = false;

        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        assert!(
            resp.headers()
                .get("Strict-Transport-Security")
                .ok()
                .flatten()
                .is_none(),
            "HSTS header should not be present when enable_hsts is false"
        );
        Ok(())
    }

    // ── EIL-027: version fields stored but never emitted ───────────────

    #[test]
    fn test_version_fields_stored_internally() {
        let config = SecurityHeadersConfig::production()
            .with_api_version("5.0.0".to_string())
            .with_worker_version("5.0.0".to_string());

        // Internal state holds the values
        assert_eq!(config.api_version, Some("5.0.0".to_string()));
        assert_eq!(config.worker_version, Some("5.0.0".to_string()));
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_version_fields_never_emitted_even_when_set() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production()
            .with_api_version("5.0.0".to_string())
            .with_worker_version("5.0.0".to_string());

        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let h = resp.headers();
        assert!(h.get("X-API-Version").ok().flatten().is_none());
        assert!(h.get("X-Worker-Version").ok().flatten().is_none());
        assert!(h.get("Server").ok().flatten().is_none());
        assert!(h.get("X-Powered-By").ok().flatten().is_none());
        Ok(())
    }

    // ── CacheControlPolicy equality edge cases ─────────────────────────

    #[test]
    fn test_cache_control_policy_same_ttl_different_variant() {
        // Same TTL value, different variant
        assert_ne!(
            CacheControlPolicy::PublicShortTtl(300),
            CacheControlPolicy::PublicMediumTtl(300)
        );
        assert_ne!(
            CacheControlPolicy::PublicMediumTtl(300),
            CacheControlPolicy::PublicLongTtl(300)
        );
        assert_ne!(
            CacheControlPolicy::PublicShortTtl(300),
            CacheControlPolicy::PublicLongTtl(300)
        );
    }

    #[test]
    fn test_cache_control_policy_custom_equality() {
        assert_eq!(
            CacheControlPolicy::Custom("abc".to_string()),
            CacheControlPolicy::Custom("abc".to_string())
        );
        assert_ne!(
            CacheControlPolicy::Custom("abc".to_string()),
            CacheControlPolicy::Custom("def".to_string())
        );
    }

    // ── Response status codes do not affect headers ─────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_headers_applied_on_404() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production();
        let mut resp = worker::Response::empty()?.with_status(404);
        add_security_headers(&mut resp, &config)?;

        let h = resp.headers();
        assert_eq!(
            h.get("X-Content-Type-Options").ok().flatten().as_deref(),
            Some("nosniff")
        );
        assert_eq!(
            h.get("X-Frame-Options").ok().flatten().as_deref(),
            Some("DENY")
        );
        assert!(h.get("Strict-Transport-Security").ok().flatten().is_some());
        assert!(h.get("Content-Security-Policy").ok().flatten().is_some());
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_headers_applied_on_204() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production();
        let mut resp = worker::Response::empty()?.with_status(204);
        add_security_headers(&mut resp, &config)?;

        let h = resp.headers();
        assert_eq!(
            h.get("X-Content-Type-Options").ok().flatten().as_deref(),
            Some("nosniff")
        );
        assert_eq!(
            h.get("X-Frame-Options").ok().flatten().as_deref(),
            Some("DENY")
        );
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_headers_applied_on_301() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production();
        let mut resp = worker::Response::empty()?.with_status(301);
        add_security_headers(&mut resp, &config)?;

        let h = resp.headers();
        assert_eq!(
            h.get("X-Content-Type-Options").ok().flatten().as_deref(),
            Some("nosniff")
        );
        assert_eq!(
            h.get("Referrer-Policy").ok().flatten().as_deref(),
            Some("no-referrer")
        );
        Ok(())
    }

    // ── Custom CSP on custom profile with CSP enabled ──────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_custom_profile_with_custom_csp_enabled() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = SecurityHeadersConfig::custom();
        config.enable_csp = true;
        config.csp_policy = Some("script-src 'none'".to_string());

        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let csp = resp
            .headers()
            .get("Content-Security-Policy")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(csp, "script-src 'none'");
        Ok(())
    }

    // ── NoCache includes all belt-and-braces headers ───────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_no_cache_pragma_and_expires() -> Result<(), Box<dyn std::error::Error>> {
        let config = SecurityHeadersConfig::production();
        let mut resp = worker::Response::empty()?.with_status(200);
        add_security_headers(&mut resp, &config)?;

        let h = resp.headers();
        assert_eq!(h.get("Pragma").ok().flatten().as_deref(), Some("no-cache"));
        assert_eq!(h.get("Expires").ok().flatten().as_deref(), Some("0"));
        Ok(())
    }

    // ── Builder from each profile ──────────────────────────────────────

    #[test]
    fn test_builder_from_development() {
        let config = SecurityHeadersConfig::development()
            .with_api_version("dev-custom".to_string())
            .with_cache_control(CacheControlPolicy::PublicMediumTtl(180));

        assert_eq!(config.profile, SecurityProfile::Development);
        assert_eq!(config.api_version, Some("dev-custom".to_string()));
        assert_eq!(
            config.cache_control_policy,
            CacheControlPolicy::PublicMediumTtl(180)
        );
        // HSTS should still be off from development base
        assert!(!config.enable_hsts);
    }

    #[test]
    fn test_builder_from_custom() {
        let config = SecurityHeadersConfig::custom()
            .with_csp_policy("default-src https:".to_string())
            .with_cache_control(CacheControlPolicy::PublicLongTtl(86400));

        assert_eq!(config.profile, SecurityProfile::Custom);
        assert_eq!(config.csp_policy, Some("default-src https:".to_string()));
        assert_eq!(
            config.cache_control_policy,
            CacheControlPolicy::PublicLongTtl(86400)
        );
        // CSP flag still off from custom base (policy stored but not enabled)
        assert!(!config.enable_csp);
    }
}
