// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust
//! Sec-Fetch-* Metadata Validation Middleware for the hosted verification flow.
//!
//! This middleware provides defence-in-depth protection against CSRF, clickjacking,
//! and request smuggling attacks by validating Fetch Metadata Request Headers.
//!
//! # ASVS Requirements
//!
//! - 3.5.8 \[L3\]: "Verify that the application has protection against origin confusion attacks."
//!
//! # Fetch Metadata Headers
//!
//! Modern browsers automatically send Sec-Fetch-* headers with requests.
//!
//! ## Sec-Fetch-Site
//!
//! Relationship between request origin and target origin. Values:
//! `same-origin` (most secure), `same-site` (different subdomain),
//! `cross-site` (potential CSRF), `none` (direct navigation).
//!
//! ## Sec-Fetch-Mode
//!
//! How the fetch was initiated. Values: `navigate` (address bar, link
//! click), `cors`, `no-cors` (simple cross-origin), `same-origin`,
//! `websocket`.
//!
//! ## Sec-Fetch-Dest
//!
//! Destination of the request. Values: `document` (HTML page), `empty`
//! (fetch/XHR), `iframe` (clickjacking risk), `script`, `image`, `style`,
//! etc.
//!
//! # Policy Modes
//!
//! Strict mode enforces validation and rejects violations (admin endpoints).
//! Lenient mode logs violations without rejecting (user endpoints).
//! Disabled mode skips validation entirely (testing and compatibility).
//!
//! # Browser Compatibility
//!
//! Sec-Fetch headers are supported in:
//! - Chrome/Edge 76+
//! - Firefox 90+
//! - Safari 15.4+
//!
//! Older browsers don't send these headers. This middleware gracefully degrades
//! by logging missing headers but not rejecting requests.

use crate::error::ApiError;
use worker::Request;

/// Sec-Fetch validation policy enforcement levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecFetchPolicy {
    /// Strict mode: Reject requests that fail validation
    /// Used for admin endpoints and sensitive operations
    Strict,

    /// Lenient mode: Log violations but allow requests
    /// Used for user-facing endpoints
    Lenient,

    /// Disabled: No validation (testing/compatibility)
    Disabled,
}

/// Configuration for Sec-Fetch validation
#[derive(Debug, Clone)]
pub struct SecFetchConfig {
    /// Policy enforcement level
    pub policy: SecFetchPolicy,

    /// Whether to reject requests from iframes (clickjacking prevention)
    pub reject_iframe_requests: bool,

    /// Whether to require Sec-Fetch headers (strict mode only)
    /// If false, missing headers are logged but not rejected
    pub require_headers: bool,

    /// Endpoint path (for logging)
    pub endpoint: String,
}

impl SecFetchConfig {
    /// Create strict configuration for admin endpoints
    pub fn strict(endpoint: impl Into<String>) -> Self {
        Self {
            policy: SecFetchPolicy::Strict,
            reject_iframe_requests: true,
            require_headers: false, // Graceful degradation for older browsers
            endpoint: endpoint.into(),
        }
    }

    /// Create lenient configuration for user endpoints
    pub fn lenient(endpoint: impl Into<String>) -> Self {
        Self {
            policy: SecFetchPolicy::Lenient,
            reject_iframe_requests: false,
            require_headers: false,
            endpoint: endpoint.into(),
        }
    }

    /// Create disabled configuration (no validation)
    pub fn disabled(endpoint: impl Into<String>) -> Self {
        Self {
            policy: SecFetchPolicy::Disabled,
            reject_iframe_requests: false,
            require_headers: false,
            endpoint: endpoint.into(),
        }
    }
}

/// Sec-Fetch-Site header values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecFetchSite {
    SameOrigin,
    SameSite,
    CrossSite,
    None,
}

impl SecFetchSite {
    /// Parse Sec-Fetch-Site header value
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_lowercase().as_str() {
            "same-origin" => Some(Self::SameOrigin),
            "same-site" => Some(Self::SameSite),
            "cross-site" => Some(Self::CrossSite),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    /// Check if this value is acceptable for strict mode
    pub fn is_strict_valid(&self) -> bool {
        matches!(self, Self::SameOrigin | Self::None)
    }

    /// Check if this value is acceptable for lenient mode.
    /// WI-01: CrossSite is permitted because the provii-verifier SDK runs on
    /// customer websites (cross-origin by design).
    pub fn is_lenient_valid(&self) -> bool {
        matches!(
            self,
            Self::SameOrigin | Self::SameSite | Self::CrossSite | Self::None
        )
    }
}

/// Sec-Fetch-Mode header values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecFetchMode {
    Navigate,
    Cors,
    NoCors,
    SameOrigin,
    Websocket,
}

impl SecFetchMode {
    /// Parse Sec-Fetch-Mode header value
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_lowercase().as_str() {
            "navigate" => Some(Self::Navigate),
            "cors" => Some(Self::Cors),
            "no-cors" => Some(Self::NoCors),
            "same-origin" => Some(Self::SameOrigin),
            "websocket" => Some(Self::Websocket),
            _ => None,
        }
    }

    /// Check if this value is acceptable.
    /// CH-039/CH-041: `no-cors` is rejected (aligns with provii-verifier).
    /// WI-01: `websocket` is permitted for WS upgrade requests.
    pub fn is_valid(&self) -> bool {
        matches!(
            self,
            Self::Navigate | Self::Cors | Self::SameOrigin | Self::Websocket
        )
    }
}

/// Sec-Fetch-Dest header values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecFetchDest {
    Document,
    Empty,
    Iframe,
    Script,
    Style,
    Image,
    Font,
    Audio,
    Video,
    Other,
}

impl SecFetchDest {
    /// Parse Sec-Fetch-Dest header value.
    /// CH-045: Unknown values return `None` so strict mode can reject them.
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_lowercase().as_str() {
            "document" => Some(Self::Document),
            "empty" => Some(Self::Empty),
            "iframe" => Some(Self::Iframe),
            "script" => Some(Self::Script),
            "style" => Some(Self::Style),
            "image" => Some(Self::Image),
            "font" => Some(Self::Font),
            "audio" => Some(Self::Audio),
            "video" => Some(Self::Video),
            _ => None,
        }
    }

    /// Check if this destination is an iframe (clickjacking risk)
    pub fn is_iframe(&self) -> bool {
        matches!(self, Self::Iframe)
    }
}

/// Sec-Fetch validator
pub struct SecFetchValidator {
    config: SecFetchConfig,
}

impl SecFetchValidator {
    /// Create a new validator with the given configuration
    pub fn new(config: SecFetchConfig) -> Self {
        Self { config }
    }

    /// Validate Sec-Fetch-* headers on a request
    ///
    /// # Returns
    ///
    /// - `Ok(())` if validation passes or policy is lenient
    /// - `Err(ApiError)` if validation fails and policy is strict
    pub fn validate(&self, req: &Request) -> Result<(), ApiError> {
        // Skip validation if policy is disabled
        if self.config.policy == SecFetchPolicy::Disabled {
            return Ok(());
        }

        let headers = req.headers();

        // Extract Sec-Fetch-* headers
        let site_header = headers.get("Sec-Fetch-Site").ok().flatten();
        let mode_header = headers.get("Sec-Fetch-Mode").ok().flatten();
        let dest_header = headers.get("Sec-Fetch-Dest").ok().flatten();

        // Check if headers are present
        let headers_present =
            site_header.is_some() || mode_header.is_some() || dest_header.is_some();

        if !headers_present {
            // Older browsers don't send Sec-Fetch headers
            self.log_missing_headers(req);

            if self.config.require_headers && self.config.policy == SecFetchPolicy::Strict {
                return Err(ApiError::Forbidden(Some(
                    "Sec-Fetch headers required but not present".to_string(),
                )));
            }

            // Graceful degradation: allow the request
            return Ok(());
        }

        // Validate Sec-Fetch-Site
        if let Some(site_value) = site_header {
            if let Some(site) = SecFetchSite::parse(&site_value) {
                let valid = match self.config.policy {
                    SecFetchPolicy::Strict => site.is_strict_valid(),
                    SecFetchPolicy::Lenient => site.is_lenient_valid(),
                    SecFetchPolicy::Disabled => true,
                };

                if !valid {
                    self.log_site_violation(req, &site_value, site);

                    if self.config.policy == SecFetchPolicy::Strict {
                        // EIL-019: Do not echo attacker-supplied header values back
                        return Err(ApiError::Forbidden(Some(
                            "Request origin not allowed".to_string(),
                        )));
                    }
                }
            } else {
                // CH-040: Reject unparseable Sec-Fetch-Site in strict mode
                self.log_invalid_header(req, "Sec-Fetch-Site", &site_value);
                if self.config.policy == SecFetchPolicy::Strict {
                    return Err(ApiError::Forbidden(Some(
                        "Request origin not allowed".to_string(),
                    )));
                }
            }
        }

        // Validate Sec-Fetch-Mode
        if let Some(mode_value) = mode_header {
            if let Some(mode) = SecFetchMode::parse(&mode_value) {
                if !mode.is_valid() {
                    self.log_mode_violation(req, &mode_value, mode);

                    if self.config.policy == SecFetchPolicy::Strict {
                        // EIL-019: Do not echo attacker-supplied header values back
                        return Err(ApiError::Forbidden(Some(
                            "Request mode not allowed".to_string(),
                        )));
                    }
                }
            } else {
                // CH-042: Reject unparseable Sec-Fetch-Mode in strict mode
                self.log_invalid_header(req, "Sec-Fetch-Mode", &mode_value);
                if self.config.policy == SecFetchPolicy::Strict {
                    return Err(ApiError::Forbidden(Some(
                        "Request mode not allowed".to_string(),
                    )));
                }
            }
        }

        // Validate Sec-Fetch-Dest (clickjacking prevention)
        if let Some(dest_value) = dest_header {
            if let Some(dest) = SecFetchDest::parse(&dest_value) {
                if dest.is_iframe() && self.config.reject_iframe_requests {
                    self.log_iframe_violation(req, &dest_value);

                    if self.config.policy == SecFetchPolicy::Strict {
                        // EIL-019: Generic message; do not explain the specific policy
                        return Err(ApiError::Forbidden(Some("Request not allowed".to_string())));
                    }
                }
            } else {
                // CH-045: Reject unknown Sec-Fetch-Dest values in strict mode
                self.log_invalid_header(req, "Sec-Fetch-Dest", &dest_value);
                if self.config.policy == SecFetchPolicy::Strict {
                    return Err(ApiError::Forbidden(Some("Request not allowed".to_string())));
                }
            }
        }

        Ok(())
    }

    /// Collect violations without rejecting the request.
    ///
    /// Returns a list of human-readable violation descriptions. An empty
    /// list means no violations were detected (or headers were absent and
    /// graceful degradation applies).
    pub fn collect_violations(&self, req: &Request) -> Vec<String> {
        let mut violations = Vec::new();

        if self.config.policy == SecFetchPolicy::Disabled {
            return violations;
        }

        let headers = req.headers();

        let site_header = headers.get("Sec-Fetch-Site").ok().flatten();
        let mode_header = headers.get("Sec-Fetch-Mode").ok().flatten();
        let dest_header = headers.get("Sec-Fetch-Dest").ok().flatten();

        let headers_present =
            site_header.is_some() || mode_header.is_some() || dest_header.is_some();

        if !headers_present {
            // Missing headers in older browsers are not violations
            return violations;
        }

        if let Some(site_value) = site_header {
            if let Some(site) = SecFetchSite::parse(&site_value) {
                let valid = match self.config.policy {
                    SecFetchPolicy::Strict => site.is_strict_valid(),
                    SecFetchPolicy::Lenient => site.is_lenient_valid(),
                    SecFetchPolicy::Disabled => true,
                };
                if !valid {
                    violations.push(format!("Sec-Fetch-Site={}", site_value));
                }
            } else {
                violations.push(format!("Sec-Fetch-Site invalid value: {}", site_value));
            }
        }

        if let Some(mode_value) = mode_header {
            if let Some(mode) = SecFetchMode::parse(&mode_value) {
                if !mode.is_valid() {
                    violations.push(format!("Sec-Fetch-Mode={}", mode_value));
                }
            } else {
                violations.push(format!("Sec-Fetch-Mode invalid value: {}", mode_value));
            }
        }

        if let Some(dest_value) = dest_header {
            if let Some(dest) = SecFetchDest::parse(&dest_value) {
                if dest.is_iframe() && self.config.reject_iframe_requests {
                    violations.push("Sec-Fetch-Dest=iframe (clickjacking)".to_string());
                }
            } else {
                // CH-045: Unknown dest values are violations
                violations.push(format!("Sec-Fetch-Dest unknown value: {}", dest_value));
            }
        }

        violations
    }

    /// Log missing Sec-Fetch headers
    fn log_missing_headers(&self, req: &Request) {
        let _method = req.method();
        let _path = req.path();

        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "SEC-FETCH INFO: Missing Sec-Fetch headers (older browser?) - {} {} - endpoint: {} - policy: {:?}",
            _method,
            _path,
            self.config.endpoint,
            self.config.policy
        );
    }

    /// Log Sec-Fetch-Site violation
    fn log_site_violation(&self, req: &Request, _value: &str, _site: SecFetchSite) {
        let _method = req.method();
        let _path = req.path();

        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "SEC-FETCH VIOLATION: Invalid Sec-Fetch-Site - {} {} - endpoint: {} - value: {} - parsed: {:?} - policy: {:?}",
            _method,
            _path,
            self.config.endpoint,
            _value,
            _site,
            self.config.policy
        );
    }

    /// Log Sec-Fetch-Mode violation
    fn log_mode_violation(&self, req: &Request, _value: &str, _mode: SecFetchMode) {
        let _method = req.method();
        let _path = req.path();

        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "SEC-FETCH VIOLATION: Invalid Sec-Fetch-Mode - {} {} - endpoint: {} - value: {} - parsed: {:?} - policy: {:?}",
            _method,
            _path,
            self.config.endpoint,
            _value,
            _mode,
            self.config.policy
        );
    }

    /// Log iframe request violation (clickjacking attempt)
    fn log_iframe_violation(&self, req: &Request, _value: &str) {
        let _method = req.method();
        let _path = req.path();

        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "SEC-FETCH VIOLATION: Request from iframe (clickjacking attempt) - {} {} - endpoint: {} - dest: {} - policy: {:?}",
            _method,
            _path,
            self.config.endpoint,
            _value,
            self.config.policy
        );
    }

    /// Log invalid header value
    fn log_invalid_header(&self, req: &Request, _header_name: &str, _value: &str) {
        let _method = req.method();
        let _path = req.path();

        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "SEC-FETCH WARNING: Invalid {} header value - {} {} - endpoint: {} - value: {} - policy: {:?}",
            _header_name,
            _method,
            _path,
            self.config.endpoint,
            _value,
            self.config.policy
        );
    }
}

/// Validate Sec-Fetch headers on a request with lenient policy
///
/// This is a convenience function for lenient validation.
///
/// # Arguments
///
/// * `req` - HTTP request to validate
/// * `endpoint` - Endpoint path for logging
///
/// # Returns
///
/// A `Vec<String>` containing descriptions of any violations detected (empty
/// if none). Lenient mode never rejects requests.
pub fn validate_sec_fetch_lenient(req: &Request, endpoint: &str) -> Vec<String> {
    let config = SecFetchConfig::lenient(endpoint);
    let validator = SecFetchValidator::new(config);

    // Lenient mode never rejects requests; collect violations for audit logging
    validator.collect_violations(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sec_fetch_site_parse() {
        assert_eq!(
            SecFetchSite::parse("same-origin"),
            Some(SecFetchSite::SameOrigin)
        );
        assert_eq!(
            SecFetchSite::parse("same-site"),
            Some(SecFetchSite::SameSite)
        );
        assert_eq!(
            SecFetchSite::parse("cross-site"),
            Some(SecFetchSite::CrossSite)
        );
        assert_eq!(SecFetchSite::parse("none"), Some(SecFetchSite::None));
        assert_eq!(
            SecFetchSite::parse("SAME-ORIGIN"),
            Some(SecFetchSite::SameOrigin)
        );
        assert_eq!(SecFetchSite::parse("invalid"), None);
    }

    #[test]
    fn test_sec_fetch_site_strict_valid() {
        assert!(SecFetchSite::SameOrigin.is_strict_valid());
        assert!(SecFetchSite::None.is_strict_valid());
        assert!(!SecFetchSite::SameSite.is_strict_valid());
        assert!(!SecFetchSite::CrossSite.is_strict_valid());
    }

    #[test]
    fn test_sec_fetch_site_lenient_valid() {
        assert!(SecFetchSite::SameOrigin.is_lenient_valid());
        assert!(SecFetchSite::SameSite.is_lenient_valid());
        assert!(SecFetchSite::None.is_lenient_valid());
        // WI-01: cross-site is now accepted in lenient mode (SDK is cross-origin)
        assert!(SecFetchSite::CrossSite.is_lenient_valid());
    }

    #[test]
    fn test_sec_fetch_mode_parse() {
        assert_eq!(
            SecFetchMode::parse("navigate"),
            Some(SecFetchMode::Navigate)
        );
        assert_eq!(SecFetchMode::parse("cors"), Some(SecFetchMode::Cors));
        assert_eq!(SecFetchMode::parse("no-cors"), Some(SecFetchMode::NoCors));
        assert_eq!(
            SecFetchMode::parse("same-origin"),
            Some(SecFetchMode::SameOrigin)
        );
        assert_eq!(
            SecFetchMode::parse("websocket"),
            Some(SecFetchMode::Websocket)
        );
        assert_eq!(SecFetchMode::parse("CORS"), Some(SecFetchMode::Cors));
        assert_eq!(SecFetchMode::parse("invalid"), None);
    }

    #[test]
    fn test_sec_fetch_mode_valid() {
        assert!(SecFetchMode::Navigate.is_valid());
        assert!(SecFetchMode::Cors.is_valid());
        // CH-039/CH-041: no-cors is now rejected
        assert!(!SecFetchMode::NoCors.is_valid());
        assert!(SecFetchMode::SameOrigin.is_valid());
        // WI-01: websocket is now accepted for WS upgrade requests
        assert!(SecFetchMode::Websocket.is_valid());
    }

    #[test]
    fn test_sec_fetch_dest_parse() {
        assert_eq!(
            SecFetchDest::parse("document"),
            Some(SecFetchDest::Document)
        );
        assert_eq!(SecFetchDest::parse("empty"), Some(SecFetchDest::Empty));
        assert_eq!(SecFetchDest::parse("iframe"), Some(SecFetchDest::Iframe));
        assert_eq!(SecFetchDest::parse("script"), Some(SecFetchDest::Script));
        assert_eq!(SecFetchDest::parse("IFRAME"), Some(SecFetchDest::Iframe));
        // CH-045: Unknown values now return None
        assert_eq!(SecFetchDest::parse("unknown"), None);
    }

    #[test]
    fn test_sec_fetch_dest_iframe() {
        assert!(SecFetchDest::Iframe.is_iframe());
        assert!(!SecFetchDest::Empty.is_iframe());
        assert!(!SecFetchDest::Document.is_iframe());
    }

    #[test]
    fn test_config_strict() {
        let config = SecFetchConfig::strict("/admin/test");
        assert_eq!(config.policy, SecFetchPolicy::Strict);
        assert!(config.reject_iframe_requests);
        assert_eq!(config.endpoint, "/admin/test");
    }

    #[test]
    fn test_config_lenient() {
        let config = SecFetchConfig::lenient("/user/test");
        assert_eq!(config.policy, SecFetchPolicy::Lenient);
        assert!(!config.reject_iframe_requests);
        assert_eq!(config.endpoint, "/user/test");
    }

    #[test]
    fn test_config_disabled() {
        let config = SecFetchConfig::disabled("/health");
        assert_eq!(config.policy, SecFetchPolicy::Disabled);
        assert!(!config.reject_iframe_requests);
        assert_eq!(config.endpoint, "/health");
    }

    // =========================================================================
    // SecFetchDest::parse():remaining variants
    // =========================================================================

    #[test]
    fn test_sec_fetch_dest_parse_style() {
        assert_eq!(SecFetchDest::parse("style"), Some(SecFetchDest::Style));
    }

    #[test]
    fn test_sec_fetch_dest_parse_image() {
        assert_eq!(SecFetchDest::parse("image"), Some(SecFetchDest::Image));
    }

    #[test]
    fn test_sec_fetch_dest_parse_font() {
        assert_eq!(SecFetchDest::parse("font"), Some(SecFetchDest::Font));
    }

    #[test]
    fn test_sec_fetch_dest_parse_audio() {
        assert_eq!(SecFetchDest::parse("audio"), Some(SecFetchDest::Audio));
    }

    #[test]
    fn test_sec_fetch_dest_parse_video() {
        assert_eq!(SecFetchDest::parse("video"), Some(SecFetchDest::Video));
    }

    // =========================================================================
    // SecFetchDest::is_iframe():exhaustive variant coverage
    // =========================================================================

    #[test]
    fn test_sec_fetch_dest_is_iframe_exhaustive() {
        // Only Iframe returns true; every other variant must return false
        assert!(!SecFetchDest::Script.is_iframe());
        assert!(!SecFetchDest::Style.is_iframe());
        assert!(!SecFetchDest::Image.is_iframe());
        assert!(!SecFetchDest::Font.is_iframe());
        assert!(!SecFetchDest::Audio.is_iframe());
        assert!(!SecFetchDest::Video.is_iframe());
        assert!(!SecFetchDest::Other.is_iframe());
    }

    // =========================================================================
    // Parse case-insensitivity edge cases
    // =========================================================================

    #[test]
    fn test_sec_fetch_site_parse_mixed_case() {
        assert_eq!(
            SecFetchSite::parse("Same-Origin"),
            Some(SecFetchSite::SameOrigin)
        );
        assert_eq!(
            SecFetchSite::parse("CROSS-SITE"),
            Some(SecFetchSite::CrossSite)
        );
        assert_eq!(
            SecFetchSite::parse("Same-Site"),
            Some(SecFetchSite::SameSite)
        );
        assert_eq!(SecFetchSite::parse("NONE"), Some(SecFetchSite::None));
    }

    #[test]
    fn test_sec_fetch_mode_parse_mixed_case() {
        assert_eq!(
            SecFetchMode::parse("Navigate"),
            Some(SecFetchMode::Navigate)
        );
        assert_eq!(SecFetchMode::parse("NO-CORS"), Some(SecFetchMode::NoCors));
        assert_eq!(
            SecFetchMode::parse("Same-Origin"),
            Some(SecFetchMode::SameOrigin)
        );
        assert_eq!(
            SecFetchMode::parse("WEBSOCKET"),
            Some(SecFetchMode::Websocket)
        );
    }

    #[test]
    fn test_sec_fetch_dest_parse_mixed_case() {
        assert_eq!(
            SecFetchDest::parse("Document"),
            Some(SecFetchDest::Document)
        );
        assert_eq!(SecFetchDest::parse("EMPTY"), Some(SecFetchDest::Empty));
        assert_eq!(SecFetchDest::parse("Script"), Some(SecFetchDest::Script));
        assert_eq!(SecFetchDest::parse("STYLE"), Some(SecFetchDest::Style));
        assert_eq!(SecFetchDest::parse("IMAGE"), Some(SecFetchDest::Image));
        assert_eq!(SecFetchDest::parse("Font"), Some(SecFetchDest::Font));
        assert_eq!(SecFetchDest::parse("AUDIO"), Some(SecFetchDest::Audio));
        assert_eq!(SecFetchDest::parse("VIDEO"), Some(SecFetchDest::Video));
    }

    // =========================================================================
    // Parse:empty string and whitespace edge cases
    // =========================================================================

    #[test]
    fn test_sec_fetch_site_parse_empty() {
        assert_eq!(SecFetchSite::parse(""), None);
    }

    #[test]
    fn test_sec_fetch_mode_parse_empty() {
        assert_eq!(SecFetchMode::parse(""), None);
    }

    #[test]
    fn test_sec_fetch_dest_parse_empty() {
        assert_eq!(SecFetchDest::parse(""), None);
    }

    #[test]
    fn test_sec_fetch_site_parse_whitespace() {
        // Leading/trailing whitespace should not match
        assert_eq!(SecFetchSite::parse(" same-origin"), None);
        assert_eq!(SecFetchSite::parse("same-origin "), None);
        assert_eq!(SecFetchSite::parse(" none "), None);
    }

    #[test]
    fn test_sec_fetch_mode_parse_whitespace() {
        assert_eq!(SecFetchMode::parse(" cors"), None);
        assert_eq!(SecFetchMode::parse("cors "), None);
        assert_eq!(SecFetchMode::parse(" navigate "), None);
    }

    #[test]
    fn test_sec_fetch_dest_parse_whitespace() {
        assert_eq!(SecFetchDest::parse(" empty"), None);
        assert_eq!(SecFetchDest::parse("empty "), None);
        assert_eq!(SecFetchDest::parse(" iframe "), None);
    }

    // =========================================================================
    // Parse:garbage and special-character inputs
    // =========================================================================

    #[test]
    fn test_sec_fetch_site_parse_garbage() {
        assert_eq!(SecFetchSite::parse("cross-origin"), None);
        assert_eq!(SecFetchSite::parse("same"), None);
        assert_eq!(SecFetchSite::parse("null"), None);
        assert_eq!(SecFetchSite::parse("same-origin\n"), None);
        assert_eq!(SecFetchSite::parse("same-origin\0"), None);
    }

    #[test]
    fn test_sec_fetch_mode_parse_garbage() {
        assert_eq!(SecFetchMode::parse("fetch"), None);
        assert_eq!(SecFetchMode::parse("cors-preflight"), None);
        assert_eq!(SecFetchMode::parse("null"), None);
        assert_eq!(SecFetchMode::parse("navigate\n"), None);
        assert_eq!(SecFetchMode::parse("cors\0"), None);
    }

    #[test]
    fn test_sec_fetch_dest_parse_garbage() {
        assert_eq!(SecFetchDest::parse("worker"), None);
        assert_eq!(SecFetchDest::parse("sharedworker"), None);
        assert_eq!(SecFetchDest::parse("object"), None);
        assert_eq!(SecFetchDest::parse("embed"), None);
        assert_eq!(SecFetchDest::parse("iframe\n"), None);
    }

    // =========================================================================
    // SecFetchConfig:require_headers defaults
    // =========================================================================

    #[test]
    fn test_config_strict_require_headers_default_false() {
        let config = SecFetchConfig::strict("/admin");
        // Graceful degradation: require_headers is false by default
        assert!(!config.require_headers);
    }

    #[test]
    fn test_config_lenient_require_headers_default_false() {
        let config = SecFetchConfig::lenient("/user");
        assert!(!config.require_headers);
    }

    #[test]
    fn test_config_disabled_require_headers_default_false() {
        let config = SecFetchConfig::disabled("/health");
        assert!(!config.require_headers);
    }

    // =========================================================================
    // SecFetchConfig:endpoint type acceptance
    // =========================================================================

    #[test]
    fn test_config_strict_string_owned() {
        let endpoint = String::from("/admin/owned");
        let config = SecFetchConfig::strict(endpoint);
        assert_eq!(config.endpoint, "/admin/owned");
    }

    #[test]
    fn test_config_lenient_string_owned() {
        let endpoint = String::from("/user/owned");
        let config = SecFetchConfig::lenient(endpoint);
        assert_eq!(config.endpoint, "/user/owned");
    }

    #[test]
    fn test_config_disabled_string_owned() {
        let endpoint = String::from("/health/owned");
        let config = SecFetchConfig::disabled(endpoint);
        assert_eq!(config.endpoint, "/health/owned");
    }

    #[test]
    fn test_config_endpoint_empty_string() {
        let config = SecFetchConfig::strict("");
        assert_eq!(config.endpoint, "");
    }

    #[test]
    fn test_config_endpoint_long_path() {
        let long = "/a".repeat(500);
        let config = SecFetchConfig::lenient(long.clone());
        assert_eq!(config.endpoint, long);
    }

    // =========================================================================
    // SecFetchValidator::new():construction
    // =========================================================================

    #[test]
    fn test_validator_new_stores_config_strict() {
        let config = SecFetchConfig::strict("/admin/test");
        let validator = SecFetchValidator::new(config);
        assert_eq!(validator.config.policy, SecFetchPolicy::Strict);
        assert!(validator.config.reject_iframe_requests);
        assert_eq!(validator.config.endpoint, "/admin/test");
    }

    #[test]
    fn test_validator_new_stores_config_lenient() {
        let config = SecFetchConfig::lenient("/user/test");
        let validator = SecFetchValidator::new(config);
        assert_eq!(validator.config.policy, SecFetchPolicy::Lenient);
        assert!(!validator.config.reject_iframe_requests);
        assert_eq!(validator.config.endpoint, "/user/test");
    }

    #[test]
    fn test_validator_new_stores_config_disabled() {
        let config = SecFetchConfig::disabled("/health");
        let validator = SecFetchValidator::new(config);
        assert_eq!(validator.config.policy, SecFetchPolicy::Disabled);
        assert!(!validator.config.reject_iframe_requests);
    }

    // =========================================================================
    // SecFetchPolicy:trait derivations
    // =========================================================================

    #[test]
    fn test_policy_eq() {
        assert_eq!(SecFetchPolicy::Strict, SecFetchPolicy::Strict);
        assert_eq!(SecFetchPolicy::Lenient, SecFetchPolicy::Lenient);
        assert_eq!(SecFetchPolicy::Disabled, SecFetchPolicy::Disabled);
    }

    #[test]
    fn test_policy_ne() {
        assert_ne!(SecFetchPolicy::Strict, SecFetchPolicy::Lenient);
        assert_ne!(SecFetchPolicy::Strict, SecFetchPolicy::Disabled);
        assert_ne!(SecFetchPolicy::Lenient, SecFetchPolicy::Disabled);
    }

    #[test]
    fn test_policy_clone() {
        let p = SecFetchPolicy::Strict;
        let p2 = p;
        assert_eq!(p, p2);
    }

    #[test]
    fn test_policy_debug() {
        let debug = format!("{:?}", SecFetchPolicy::Strict);
        assert_eq!(debug, "Strict");
        let debug = format!("{:?}", SecFetchPolicy::Lenient);
        assert_eq!(debug, "Lenient");
        let debug = format!("{:?}", SecFetchPolicy::Disabled);
        assert_eq!(debug, "Disabled");
    }

    // =========================================================================
    // SecFetchSite:trait derivations
    // =========================================================================

    #[test]
    fn test_site_clone_copy() {
        let s = SecFetchSite::SameOrigin;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn test_site_debug() {
        assert_eq!(format!("{:?}", SecFetchSite::SameOrigin), "SameOrigin");
        assert_eq!(format!("{:?}", SecFetchSite::SameSite), "SameSite");
        assert_eq!(format!("{:?}", SecFetchSite::CrossSite), "CrossSite");
        assert_eq!(format!("{:?}", SecFetchSite::None), "None");
    }

    #[test]
    fn test_site_ne() {
        assert_ne!(SecFetchSite::SameOrigin, SecFetchSite::CrossSite);
        assert_ne!(SecFetchSite::SameSite, SecFetchSite::None);
    }

    // =========================================================================
    // SecFetchMode:trait derivations
    // =========================================================================

    #[test]
    fn test_mode_clone_copy() {
        let m = SecFetchMode::Cors;
        let m2 = m;
        assert_eq!(m, m2);
    }

    #[test]
    fn test_mode_debug() {
        assert_eq!(format!("{:?}", SecFetchMode::Navigate), "Navigate");
        assert_eq!(format!("{:?}", SecFetchMode::Cors), "Cors");
        assert_eq!(format!("{:?}", SecFetchMode::NoCors), "NoCors");
        assert_eq!(format!("{:?}", SecFetchMode::SameOrigin), "SameOrigin");
        assert_eq!(format!("{:?}", SecFetchMode::Websocket), "Websocket");
    }

    #[test]
    fn test_mode_ne() {
        assert_ne!(SecFetchMode::Navigate, SecFetchMode::Cors);
        assert_ne!(SecFetchMode::NoCors, SecFetchMode::SameOrigin);
    }

    // =========================================================================
    // SecFetchDest:trait derivations
    // =========================================================================

    #[test]
    fn test_dest_clone_copy() {
        let d = SecFetchDest::Iframe;
        let d2 = d;
        assert_eq!(d, d2);
    }

    #[test]
    fn test_dest_debug() {
        assert_eq!(format!("{:?}", SecFetchDest::Document), "Document");
        assert_eq!(format!("{:?}", SecFetchDest::Empty), "Empty");
        assert_eq!(format!("{:?}", SecFetchDest::Iframe), "Iframe");
        assert_eq!(format!("{:?}", SecFetchDest::Script), "Script");
        assert_eq!(format!("{:?}", SecFetchDest::Style), "Style");
        assert_eq!(format!("{:?}", SecFetchDest::Image), "Image");
        assert_eq!(format!("{:?}", SecFetchDest::Font), "Font");
        assert_eq!(format!("{:?}", SecFetchDest::Audio), "Audio");
        assert_eq!(format!("{:?}", SecFetchDest::Video), "Video");
        assert_eq!(format!("{:?}", SecFetchDest::Other), "Other");
    }

    #[test]
    fn test_dest_ne() {
        assert_ne!(SecFetchDest::Document, SecFetchDest::Empty);
        assert_ne!(SecFetchDest::Iframe, SecFetchDest::Script);
        assert_ne!(SecFetchDest::Audio, SecFetchDest::Video);
    }

    // =========================================================================
    // SecFetchConfig:Clone derivation
    // =========================================================================

    #[test]
    fn test_config_clone() {
        let config = SecFetchConfig::strict("/admin/clone-test");
        let cloned = config.clone();
        assert_eq!(cloned.policy, SecFetchPolicy::Strict);
        assert!(cloned.reject_iframe_requests);
        assert!(!cloned.require_headers);
        assert_eq!(cloned.endpoint, "/admin/clone-test");
    }

    #[test]
    fn test_config_debug() {
        let config = SecFetchConfig::strict("/test");
        let debug = format!("{:?}", config);
        assert!(debug.contains("Strict"));
        assert!(debug.contains("/test"));
    }

    // =========================================================================
    // SecFetchConfig:manual field overrides after construction
    // =========================================================================

    #[test]
    fn test_config_strict_with_require_headers_override() {
        let mut config = SecFetchConfig::strict("/admin/strict-headers");
        config.require_headers = true;
        assert!(config.require_headers);
        assert_eq!(config.policy, SecFetchPolicy::Strict);
    }

    #[test]
    fn test_config_strict_with_iframe_override() {
        let mut config = SecFetchConfig::strict("/admin");
        config.reject_iframe_requests = false;
        assert!(!config.reject_iframe_requests);
    }

    #[test]
    fn test_config_lenient_with_iframe_override() {
        let mut config = SecFetchConfig::lenient("/user");
        config.reject_iframe_requests = true;
        assert!(config.reject_iframe_requests);
    }

    // =========================================================================
    // SecFetchSite::is_strict_valid / is_lenient_valid:cross-validation
    // The strict set is a proper subset of the lenient set.
    // =========================================================================

    #[test]
    fn test_strict_valid_is_subset_of_lenient_valid() {
        let all_sites = [
            SecFetchSite::SameOrigin,
            SecFetchSite::SameSite,
            SecFetchSite::CrossSite,
            SecFetchSite::None,
        ];
        for site in &all_sites {
            if site.is_strict_valid() {
                assert!(
                    site.is_lenient_valid(),
                    "{:?} is strict-valid but not lenient-valid",
                    site
                );
            }
        }
    }

    // =========================================================================
    // SecFetchMode::is_valid:NoCors is the only rejected mode
    // =========================================================================

    #[test]
    fn test_mode_is_valid_only_nocors_rejected() {
        let all_modes = [
            SecFetchMode::Navigate,
            SecFetchMode::Cors,
            SecFetchMode::NoCors,
            SecFetchMode::SameOrigin,
            SecFetchMode::Websocket,
        ];
        let rejected: Vec<_> = all_modes.iter().filter(|m| !m.is_valid()).collect();
        assert_eq!(rejected.len(), 1);
        assert_eq!(*rejected[0], SecFetchMode::NoCors);
    }

    // =========================================================================
    // SecFetchDest::parse:exhaustive round-trip for every known value
    // =========================================================================

    #[test]
    fn test_sec_fetch_dest_parse_all_known_values() {
        let cases = [
            ("document", SecFetchDest::Document),
            ("empty", SecFetchDest::Empty),
            ("iframe", SecFetchDest::Iframe),
            ("script", SecFetchDest::Script),
            ("style", SecFetchDest::Style),
            ("image", SecFetchDest::Image),
            ("font", SecFetchDest::Font),
            ("audio", SecFetchDest::Audio),
            ("video", SecFetchDest::Video),
        ];
        for (input, expected) in &cases {
            assert_eq!(
                SecFetchDest::parse(input),
                Some(*expected),
                "failed for input: {}",
                input
            );
        }
    }

    // =========================================================================
    // SecFetchSite::parse:exhaustive round-trip for every known value
    // =========================================================================

    #[test]
    fn test_sec_fetch_site_parse_all_known_values() {
        let cases = [
            ("same-origin", SecFetchSite::SameOrigin),
            ("same-site", SecFetchSite::SameSite),
            ("cross-site", SecFetchSite::CrossSite),
            ("none", SecFetchSite::None),
        ];
        for (input, expected) in &cases {
            assert_eq!(
                SecFetchSite::parse(input),
                Some(*expected),
                "failed for input: {}",
                input
            );
        }
    }

    // =========================================================================
    // SecFetchMode::parse:exhaustive round-trip for every known value
    // =========================================================================

    #[test]
    fn test_sec_fetch_mode_parse_all_known_values() {
        let cases = [
            ("navigate", SecFetchMode::Navigate),
            ("cors", SecFetchMode::Cors),
            ("no-cors", SecFetchMode::NoCors),
            ("same-origin", SecFetchMode::SameOrigin),
            ("websocket", SecFetchMode::Websocket),
        ];
        for (input, expected) in &cases {
            assert_eq!(
                SecFetchMode::parse(input),
                Some(*expected),
                "failed for input: {}",
                input
            );
        }
    }

    // =========================================================================
    // CH-045: SecFetchDest::Other is never returned by parse
    // =========================================================================

    #[test]
    fn test_sec_fetch_dest_other_never_from_parse() {
        // The Other variant exists in the enum but no string maps to it.
        // This is intentional: CH-045 says unknown values return None so
        // strict mode can reject them.
        let attempts = [
            "other",
            "Other",
            "OTHER",
            "unknown",
            "UNKNOWN",
            "track",
            "manifest",
            "paintworklet",
            "audioworklet",
            "xslt",
            "report",
        ];
        for input in &attempts {
            let parsed = SecFetchDest::parse(input);
            assert_ne!(
                parsed,
                Some(SecFetchDest::Other),
                "input '{}' should not parse to Other",
                input
            );
        }
    }

    // =========================================================================
    // SecFetchValidator config field visibility
    // =========================================================================

    #[test]
    fn test_validator_custom_config() {
        let config = SecFetchConfig {
            policy: SecFetchPolicy::Strict,
            reject_iframe_requests: false,
            require_headers: true,
            endpoint: "/custom".to_string(),
        };
        let validator = SecFetchValidator::new(config);
        assert_eq!(validator.config.policy, SecFetchPolicy::Strict);
        assert!(!validator.config.reject_iframe_requests);
        assert!(validator.config.require_headers);
        assert_eq!(validator.config.endpoint, "/custom");
    }

    #[test]
    fn test_validator_lenient_no_iframe_rejection() {
        let config = SecFetchConfig::lenient("/verify");
        let validator = SecFetchValidator::new(config);
        assert!(!validator.config.reject_iframe_requests);
        assert_eq!(validator.config.policy, SecFetchPolicy::Lenient);
    }

    // =========================================================================
    // SecFetchSite / SecFetchMode:lenient accepts everything strict accepts
    // =========================================================================

    #[test]
    fn test_lenient_superset_of_strict_for_all_sites() {
        // Lenient must accept all four values. Strict only accepts SameOrigin + None.
        assert!(SecFetchSite::SameOrigin.is_lenient_valid());
        assert!(SecFetchSite::SameSite.is_lenient_valid());
        assert!(SecFetchSite::CrossSite.is_lenient_valid());
        assert!(SecFetchSite::None.is_lenient_valid());

        assert!(SecFetchSite::SameOrigin.is_strict_valid());
        assert!(!SecFetchSite::SameSite.is_strict_valid());
        assert!(!SecFetchSite::CrossSite.is_strict_valid());
        assert!(SecFetchSite::None.is_strict_valid());
    }

    // =========================================================================
    // Determinism: parse the same value twice, get the same result
    // =========================================================================

    #[test]
    fn test_parse_deterministic_site() {
        assert_eq!(
            SecFetchSite::parse("cross-site"),
            SecFetchSite::parse("cross-site")
        );
    }

    #[test]
    fn test_parse_deterministic_mode() {
        assert_eq!(
            SecFetchMode::parse("no-cors"),
            SecFetchMode::parse("no-cors")
        );
    }

    #[test]
    fn test_parse_deterministic_dest() {
        assert_eq!(SecFetchDest::parse("iframe"), SecFetchDest::parse("iframe"));
    }

    // =========================================================================
    // SecFetchConfig:all constructors set the same require_headers default
    // =========================================================================

    #[test]
    fn test_all_constructors_default_require_headers_false() {
        let strict = SecFetchConfig::strict("/s");
        let lenient = SecFetchConfig::lenient("/l");
        let disabled = SecFetchConfig::disabled("/d");
        assert!(!strict.require_headers);
        assert!(!lenient.require_headers);
        assert!(!disabled.require_headers);
    }
}
