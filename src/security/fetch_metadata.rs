// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Sec-Fetch-* header validation for defence in depth against CSRF and XSRF attacks.
//!
//! Validates the `Sec-Fetch-Site`, `Sec-Fetch-Mode`, and `Sec-Fetch-Dest` headers
//! sent by modern browsers. These headers help detect and prevent cross-site request
//! forgery attacks where an attacker tries to make requests from an unauthorised
//! origin.
//!
//! Reference: <https://w3c.github.io/fetch-metadata/>
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use crate::error::ApiError;
use crate::security::status_auth::HeaderSource;

/// Validates `Sec-Fetch-Site` header for authenticated requests.
///
/// # Security
///
/// SECURITY: This is a CSRF defence gate. Rejecting `cross-site` prevents
/// browser-initiated cross-origin requests from reaching authenticated
/// endpoints. Missing headers are permitted for backwards compatibility with
/// older browsers and non-browser clients (mobile apps, API consumers).
///
/// # Allowed Values
///
/// Allowed values are `same-origin` (same origin), `same-site` (sibling subdomain),
/// and `none` (user-initiated navigation such as the address bar).
///
/// # Rejected Values
///
/// - `cross-site`: request originated from a different site (potential CSRF)
///
/// # Arguments
/// * `headers` - The request headers to validate
///
/// # Returns
/// - `Ok(())` if the header is absent, valid, or contains an allowed value
/// - `Err(ApiError::Forbidden)` if the header contains "cross-site" or other disallowed values
pub fn validate_sec_fetch_site(headers: &impl HeaderSource) -> Result<(), ApiError> {
    match headers.get("Sec-Fetch-Site") {
        Ok(Some(site)) => match site.to_lowercase().as_str() {
            "same-origin" | "same-site" | "none" => {
                #[cfg(target_arch = "wasm32")]
                console_log!("[SECURITY] ✅ Sec-Fetch-Site validation passed: {}", site);
                Ok(())
            }
            "cross-site" => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] ❌ Sec-Fetch-Site validation FAILED: cross-site request detected"
                );
                Err(ApiError::Forbidden(Some(
                    "Cross-site requests not allowed".to_string(),
                )))
            }
            _ => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] ❌ Sec-Fetch-Site validation FAILED: invalid value '{}'",
                    site
                );
                Err(ApiError::Forbidden(Some(
                    "Invalid Sec-Fetch-Site value".to_string(),
                )))
            }
        },
        Ok(None) => {
            // Missing headers are allowed for backwards compatibility with older browsers
            // and for non-browser clients (mobile apps, API clients) which don't send these headers.
            // The protection is that IF a browser sends these headers and they indicate cross-site,
            // we block the request.
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] ℹ️ Sec-Fetch-Site header missing (non-browser client) - allowing"
            );
            Ok(())
        }
        Err(_) => {
            // ADV-VA-020: Fail closed on header read errors. If the Workers
            // runtime cannot read the header, reject the request rather than
            // silently allowing it through, matching the strict variant.
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] ❌ Error reading Sec-Fetch-Site header - rejecting (fail closed)"
            );
            Err(ApiError::Forbidden(Some(
                "Unable to validate request metadata".to_string(),
            )))
        }
    }
}

/// Validates `Sec-Fetch-Mode` header for authenticated requests.
///
/// # Security
///
/// SECURITY: Rejects `no-cors` and `websocket` modes which are unexpected on
/// REST API endpoints and may indicate CSRF or protocol confusion attacks.
/// `navigate` is also rejected (CH-015) because browser page loads should not
/// target API routes.
///
/// # Allowed Values
///
/// - `cors`: standard CORS request
/// - `same-origin`: same-origin request
///
/// # Rejected Values
///
/// - `no-cors`: potential CSRF vector (no CORS preflight)
/// - `navigate`: browser page load, not a programmatic fetch
/// - `websocket`: unexpected in REST API context
/// - `object`: plugin-based requests are not expected
///
/// # Arguments
/// * `headers` - The request headers to validate
///
/// # Returns
/// - `Ok(())` if the header is absent, valid, or contains an allowed value
/// - `Err(ApiError::Forbidden)` if the header contains "no-cors", "websocket" or other disallowed values
pub fn validate_sec_fetch_mode(headers: &impl HeaderSource) -> Result<(), ApiError> {
    match headers.get("Sec-Fetch-Mode") {
        Ok(Some(mode)) => match mode.to_lowercase().as_str() {
            // CH-015: Reject "navigate" on API endpoints. Only programmatic
            // fetch modes (cors, same-origin) are expected; navigation indicates
            // a browser page load which should not target API routes.
            "cors" | "same-origin" => {
                #[cfg(target_arch = "wasm32")]
                console_log!("[SECURITY] ✅ Sec-Fetch-Mode validation passed: {}", mode);
                Ok(())
            }
            "navigate" => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] ❌ Sec-Fetch-Mode validation FAILED: navigate mode on API endpoint"
                );
                Err(ApiError::Forbidden(Some(
                    "Navigate mode not allowed on API endpoints".to_string(),
                )))
            }
            "no-cors" => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] ❌ Sec-Fetch-Mode validation FAILED: no-cors mode detected"
                );
                Err(ApiError::Forbidden(Some(
                    "no-cors requests not allowed".to_string(),
                )))
            }
            "websocket" => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] ❌ Sec-Fetch-Mode validation FAILED: websocket mode detected"
                );
                Err(ApiError::Forbidden(Some(
                    "WebSocket requests not allowed".to_string(),
                )))
            }
            _ => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] ❌ Sec-Fetch-Mode validation FAILED: invalid value '{}'",
                    mode
                );
                Err(ApiError::Forbidden(Some(
                    "Invalid Sec-Fetch-Mode value".to_string(),
                )))
            }
        },
        Ok(None) => {
            // Missing headers are allowed for non-browser clients (mobile apps, API clients)
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] ℹ️ Sec-Fetch-Mode header missing (non-browser client) - allowing"
            );
            Ok(())
        }
        Err(_) => {
            // ADV-VA-020: Fail closed on header read errors, matching the
            // strict variant behaviour.
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] ❌ Error reading Sec-Fetch-Mode header - rejecting (fail closed)"
            );
            Err(ApiError::Forbidden(Some(
                "Unable to validate request metadata".to_string(),
            )))
        }
    }
}

/// Validates `Sec-Fetch-Dest` header to ensure requests target expected destinations.
///
/// # Security
///
/// SECURITY (CH-018): Rejects destination values like `image`, `style`, or
/// `script` that indicate the request is embedded as a sub-resource, which is
/// not intended for API endpoints.
///
/// # Allowed Values
///
/// - `empty`: Fetch API, XMLHttpRequest, or similar programmatic request
/// - `document`: form submission or navigation
///
/// # Arguments
/// * `headers` - The request headers to validate
///
/// # Returns
/// - `Ok(())` if the header is absent or contains an allowed value
/// - `Err(ApiError::Forbidden)` if validation fails
pub fn validate_sec_fetch_dest(headers: &impl HeaderSource) -> Result<(), ApiError> {
    match headers.get("Sec-Fetch-Dest") {
        Ok(Some(dest)) => {
            match dest.to_lowercase().as_str() {
                "empty" | "document" => {
                    #[cfg(target_arch = "wasm32")]
                    console_log!("[SECURITY] ✅ Sec-Fetch-Dest validation passed: {}", dest);
                    Ok(())
                }
                _ => {
                    // CH-018: Reject unknown Sec-Fetch-Dest values. Only 'empty'
                    // (fetch/XHR) and 'document' (navigation) are expected on our
                    // API. Other values (image, style, script, etc.) indicate the
                    // request is embedded as a sub-resource, which is not intended.
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[SECURITY] ❌ Sec-Fetch-Dest validation FAILED: unexpected value '{}'",
                        dest
                    );
                    Err(ApiError::Forbidden(Some(
                        "Unexpected Sec-Fetch-Dest value".to_string(),
                    )))
                }
            }
        }
        Ok(None) => {
            // Missing headers are allowed for non-browser clients (mobile apps, API clients)
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] ℹ️ Sec-Fetch-Dest header missing (non-browser client) - allowing"
            );
            Ok(())
        }
        Err(_) => {
            // ADV-VA-020: Fail closed on header read errors, matching the
            // strict variant behaviour.
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] ❌ Error reading Sec-Fetch-Dest header - rejecting (fail closed)"
            );
            Err(ApiError::Forbidden(Some(
                "Unable to validate request metadata".to_string(),
            )))
        }
    }
}

/// Combined validation of all Sec-Fetch-* headers for authenticated endpoints.
///
/// Primary validation entry point for authenticated requests. Validates
/// `Sec-Fetch-Site`, `Sec-Fetch-Mode`, and `Sec-Fetch-Dest` in sequence,
/// short-circuiting on first failure.
///
/// # Arguments
/// * `headers` - The request headers to validate
///
/// # Returns
/// - `Ok(())` if all validations pass
/// - `Err(ApiError::Forbidden)` if any validation fails
pub fn validate_fetch_metadata(headers: &impl HeaderSource) -> Result<(), ApiError> {
    // Validate Site header (most critical for CSRF prevention)
    validate_sec_fetch_site(headers)?;

    // Validate Mode header
    validate_sec_fetch_mode(headers)?;

    // Validate Dest header (informational, non-blocking)
    validate_sec_fetch_dest(headers)?;

    Ok(())
}

/// Validates Sec-Fetch-Mode header allowing `no-cors` for browser-initiated CSP reports.
///
/// SECURITY (EA-016): Browser CSP violation reports are sent with `Sec-Fetch-Mode: no-cors`
/// per the Reporting API specification. The standard `validate_sec_fetch_mode` rejects
/// `no-cors`, which blocks legitimate CSP reports. This variant permits `no-cors`
/// specifically for the CSP report endpoint.
fn validate_sec_fetch_mode_csp(headers: &impl HeaderSource) -> Result<(), ApiError> {
    match headers.get("Sec-Fetch-Mode") {
        Ok(Some(mode)) => match mode.to_lowercase().as_str() {
            "cors" | "same-origin" | "no-cors" => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] Sec-Fetch-Mode validation passed (CSP): {}",
                    mode
                );
                Ok(())
            }
            "navigate" => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] Sec-Fetch-Mode validation FAILED (CSP): navigate mode on API endpoint"
                );
                Err(ApiError::Forbidden(Some(
                    "Navigate mode not allowed on API endpoints".to_string(),
                )))
            }
            "websocket" => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] Sec-Fetch-Mode validation FAILED (CSP): websocket mode detected"
                );
                Err(ApiError::Forbidden(Some(
                    "WebSocket requests not allowed".to_string(),
                )))
            }
            _ => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] Sec-Fetch-Mode validation FAILED (CSP): invalid value '{}'",
                    mode
                );
                Err(ApiError::Forbidden(Some(
                    "Invalid Sec-Fetch-Mode value".to_string(),
                )))
            }
        },
        Ok(None) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] Sec-Fetch-Mode header missing (non-browser client) - allowing for CSP"
            );
            Ok(())
        }
        Err(_) => {
            // ADV-VA-020: Fail closed on header read errors, matching the
            // strict variant behaviour.
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] ❌ Error reading Sec-Fetch-Mode header (CSP) - rejecting (fail closed)"
            );
            Err(ApiError::Forbidden(Some(
                "Unable to validate request metadata".to_string(),
            )))
        }
    }
}

/// Combined validation of Sec-Fetch-* headers for the CSP report endpoint.
///
/// SECURITY (EA-016): Identical to [`validate_fetch_metadata`] except it permits
/// `Sec-Fetch-Mode: no-cors`, which browsers use when sending CSP violation reports
/// via the Reporting API.
pub fn validate_fetch_metadata_csp(headers: &impl HeaderSource) -> Result<(), ApiError> {
    validate_sec_fetch_site(headers)?;
    validate_sec_fetch_mode_csp(headers)?;
    validate_sec_fetch_dest(headers)?;
    Ok(())
}

/// Strict validation of Sec-Fetch-* headers for internal service-binding routes.
///
/// Unlike [`validate_fetch_metadata`], this function **rejects** requests that are
/// missing the `Sec-Fetch-Site` header entirely. Cloudflare service binding calls
/// always include `Sec-Fetch-Site: same-origin`, so a missing header on an internal
/// route indicates a direct HTTP request from a non-service-binding source.
///
/// # Security
/// Internal endpoints should only be reachable via Cloudflare service bindings.
/// Requiring `Sec-Fetch-Site` provides defence-in-depth: even if an attacker
/// discovers the internal endpoint path, they cannot call it from outside the
/// Cloudflare service binding without also spoofing the header (which browsers
/// forbid).
///
/// # Arguments
/// * `headers` - The request headers to validate
///
/// # Returns
/// Returns `Ok(())` when `Sec-Fetch-Site` is present and passes standard validation.
/// Returns `Err(ApiError::NotFound)` when the header is absent or contains a disallowed
/// value, hiding endpoint existence from unauthorised callers in both cases.
pub fn validate_fetch_metadata_strict(headers: &impl HeaderSource) -> Result<(), ApiError> {
    // SECURITY: Require Sec-Fetch-Site header to be present on internal routes.
    // Service bindings always send this header; its absence indicates a direct
    // HTTP request bypassing the service binding layer.
    match headers.get("Sec-Fetch-Site") {
        Ok(Some(site)) => {
            let site_lower = site.to_lowercase();
            match site_lower.as_str() {
                "same-origin" | "same-site" | "none" => {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[SECURITY][INTERNAL] Sec-Fetch-Site strict validation passed: {}",
                        site
                    );
                }
                _ => {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[SECURITY][INTERNAL] Sec-Fetch-Site strict validation FAILED: {}",
                        site
                    );
                    return Err(ApiError::NotFound);
                }
            }
        }
        Ok(None) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][INTERNAL] Sec-Fetch-Site header MISSING on internal route - rejecting"
            );
            return Err(ApiError::NotFound);
        }
        Err(_) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][INTERNAL] Error reading Sec-Fetch-Site header on internal route - rejecting"
            );
            return Err(ApiError::NotFound);
        }
    }

    // Validate remaining Sec-Fetch-* headers using standard validation.
    // Map any Forbidden errors to NotFound to hide endpoint existence.
    validate_sec_fetch_mode(headers).map_err(|_| ApiError::NotFound)?;
    validate_sec_fetch_dest(headers).map_err(|_| ApiError::NotFound)?;

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::string_slice
)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct TestHeaders(HashMap<String, String>);

    impl TestHeaders {
        fn new() -> Self {
            Self(HashMap::new())
        }

        fn set(&mut self, name: &str, value: &str) {
            self.0.insert(name.to_ascii_lowercase(), value.to_string());
        }
    }

    impl HeaderSource for TestHeaders {
        fn get(&self, name: &str) -> Result<Option<String>, String> {
            Ok(self.0.get(&name.to_ascii_lowercase()).cloned())
        }
    }

    // ── validate_sec_fetch_site ───────────────────────────────────────

    #[test]
    fn test_sec_fetch_site_same_origin_passes() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        assert!(validate_sec_fetch_site(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_site_same_site_passes() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-site");
        assert!(validate_sec_fetch_site(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_site_none_passes() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "none");
        assert!(validate_sec_fetch_site(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_site_cross_site_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "cross-site");
        let result = validate_sec_fetch_site(&h);
        assert!(result.is_err());
        match result {
            Err(ApiError::Forbidden(_)) => {}
            other => panic!("expected Forbidden, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    #[test]
    fn test_sec_fetch_site_unknown_value_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "invalid-value");
        let result = validate_sec_fetch_site(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_site_missing_header_allowed() {
        let h = TestHeaders::new();
        // No Sec-Fetch-Site header.
        assert!(validate_sec_fetch_site(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_site_case_insensitive() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "SAME-ORIGIN");
        assert!(validate_sec_fetch_site(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_site_mixed_case() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "Cross-Site");
        let result = validate_sec_fetch_site(&h);
        assert!(result.is_err());
    }

    // ── validate_sec_fetch_mode ───────────────────────────────────────

    #[test]
    fn test_sec_fetch_mode_cors_passes() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "cors");
        assert!(validate_sec_fetch_mode(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_mode_same_origin_passes() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "same-origin");
        assert!(validate_sec_fetch_mode(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_mode_navigate_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "navigate");
        let result = validate_sec_fetch_mode(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_mode_no_cors_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "no-cors");
        let result = validate_sec_fetch_mode(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_mode_websocket_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "websocket");
        let result = validate_sec_fetch_mode(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_mode_unknown_value_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "custom-mode");
        let result = validate_sec_fetch_mode(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_mode_missing_header_allowed() {
        let h = TestHeaders::new();
        assert!(validate_sec_fetch_mode(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_mode_case_insensitive() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "CORS");
        assert!(validate_sec_fetch_mode(&h).is_ok());
    }

    // ── validate_sec_fetch_dest ───────────────────────────────────────

    #[test]
    fn test_sec_fetch_dest_empty_passes() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "empty");
        assert!(validate_sec_fetch_dest(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_dest_document_passes() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "document");
        assert!(validate_sec_fetch_dest(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_dest_image_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "image");
        let result = validate_sec_fetch_dest(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_dest_script_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "script");
        let result = validate_sec_fetch_dest(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_dest_style_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "style");
        let result = validate_sec_fetch_dest(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_dest_iframe_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "iframe");
        let result = validate_sec_fetch_dest(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_dest_missing_header_allowed() {
        let h = TestHeaders::new();
        assert!(validate_sec_fetch_dest(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_dest_case_insensitive() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "EMPTY");
        assert!(validate_sec_fetch_dest(&h).is_ok());
    }

    // ── validate_fetch_metadata (combined) ────────────────────────────

    #[test]
    fn test_validate_fetch_metadata_all_valid() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "cors");
        h.set("Sec-Fetch-Dest", "empty");
        assert!(validate_fetch_metadata(&h).is_ok());
    }

    #[test]
    fn test_validate_fetch_metadata_no_headers_passes() {
        let h = TestHeaders::new();
        assert!(validate_fetch_metadata(&h).is_ok());
    }

    #[test]
    fn test_validate_fetch_metadata_site_fails_short_circuits() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "cross-site");
        h.set("Sec-Fetch-Mode", "cors");
        h.set("Sec-Fetch-Dest", "empty");
        let result = validate_fetch_metadata(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_fetch_metadata_mode_fails_with_valid_site() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "websocket");
        h.set("Sec-Fetch-Dest", "empty");
        let result = validate_fetch_metadata(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_fetch_metadata_dest_fails_with_valid_site_and_mode() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "cors");
        h.set("Sec-Fetch-Dest", "image");
        let result = validate_fetch_metadata(&h);
        assert!(result.is_err());
    }

    // ── validate_fetch_metadata_csp ───────────────────────────────────

    #[test]
    fn test_validate_fetch_metadata_csp_allows_no_cors() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "no-cors");
        h.set("Sec-Fetch-Dest", "empty");
        assert!(validate_fetch_metadata_csp(&h).is_ok());
    }

    #[test]
    fn test_validate_fetch_metadata_csp_rejects_websocket() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "websocket");
        h.set("Sec-Fetch-Dest", "empty");
        let result = validate_fetch_metadata_csp(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_fetch_metadata_csp_rejects_navigate() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "navigate");
        h.set("Sec-Fetch-Dest", "empty");
        let result = validate_fetch_metadata_csp(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_fetch_metadata_csp_no_headers_passes() {
        let h = TestHeaders::new();
        assert!(validate_fetch_metadata_csp(&h).is_ok());
    }

    // ── validate_fetch_metadata_strict ─────────────────────────────────

    #[test]
    fn test_validate_fetch_metadata_strict_same_origin_passes() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "cors");
        h.set("Sec-Fetch-Dest", "empty");
        assert!(validate_fetch_metadata_strict(&h).is_ok());
    }

    #[test]
    fn test_validate_fetch_metadata_strict_missing_site_rejected() {
        let mut h = TestHeaders::new();
        // Strict mode requires Sec-Fetch-Site.
        h.set("Sec-Fetch-Mode", "cors");
        h.set("Sec-Fetch-Dest", "empty");
        let result = validate_fetch_metadata_strict(&h);
        assert!(result.is_err());
        // Returns NotFound (not Forbidden) to hide endpoint existence.
        match result {
            Err(ApiError::NotFound) => {}
            other => panic!("expected NotFound, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    #[test]
    fn test_validate_fetch_metadata_strict_cross_site_rejected_as_not_found() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "cross-site");
        h.set("Sec-Fetch-Mode", "cors");
        h.set("Sec-Fetch-Dest", "empty");
        let result = validate_fetch_metadata_strict(&h);
        match result {
            Err(ApiError::NotFound) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "strict mode cross-site should return NotFound, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_validate_fetch_metadata_strict_mode_fails_returns_not_found() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "websocket");
        h.set("Sec-Fetch-Dest", "empty");
        let result = validate_fetch_metadata_strict(&h);
        match result {
            Err(ApiError::NotFound) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "strict mode websocket should return NotFound, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_validate_fetch_metadata_strict_dest_fails_returns_not_found() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "cors");
        h.set("Sec-Fetch-Dest", "script");
        let result = validate_fetch_metadata_strict(&h);
        match result {
            Err(ApiError::NotFound) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "strict mode script dest should return NotFound, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_validate_fetch_metadata_strict_same_site_passes() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-site");
        h.set("Sec-Fetch-Mode", "same-origin");
        h.set("Sec-Fetch-Dest", "document");
        assert!(validate_fetch_metadata_strict(&h).is_ok());
    }

    #[test]
    fn test_validate_fetch_metadata_strict_none_passes() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "none");
        h.set("Sec-Fetch-Mode", "cors");
        h.set("Sec-Fetch-Dest", "empty");
        assert!(validate_fetch_metadata_strict(&h).is_ok());
    }

    // ── validate_sec_fetch_mode_csp (private, tested via public fn) ───

    #[test]
    fn test_sec_fetch_mode_csp_cors_passes() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "cors");
        h.set("Sec-Fetch-Dest", "empty");
        assert!(validate_fetch_metadata_csp(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_mode_csp_same_origin_passes() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "same-origin");
        h.set("Sec-Fetch-Dest", "empty");
        assert!(validate_fetch_metadata_csp(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_mode_csp_unknown_value_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "custom");
        h.set("Sec-Fetch-Dest", "empty");
        let result = validate_fetch_metadata_csp(&h);
        assert!(result.is_err());
    }

    // ── Error message verification ────────────────────────────────────

    #[test]
    fn test_cross_site_error_message() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "cross-site");
        match validate_sec_fetch_site(&h) {
            Err(ApiError::Forbidden(Some(msg))) => {
                assert!(msg.contains("Cross-site"));
            }
            other => panic!("expected Forbidden with message, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    #[test]
    fn test_navigate_mode_error_message() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "navigate");
        match validate_sec_fetch_mode(&h) {
            Err(ApiError::Forbidden(Some(msg))) => {
                assert!(msg.contains("Navigate"));
            }
            other => panic!("expected Forbidden with message, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    #[test]
    fn test_no_cors_error_message() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "no-cors");
        match validate_sec_fetch_mode(&h) {
            Err(ApiError::Forbidden(Some(msg))) => {
                assert!(msg.contains("no-cors"));
            }
            other => panic!("expected Forbidden with message, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    #[test]
    fn test_websocket_error_message() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "websocket");
        match validate_sec_fetch_mode(&h) {
            Err(ApiError::Forbidden(Some(msg))) => {
                assert!(msg.contains("WebSocket"));
            }
            other => panic!("expected Forbidden with message, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    // ── Additional Sec-Fetch-Site tests ───────────────────────────────

    #[test]
    fn test_sec_fetch_site_invalid_value_error_message() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "bogus");
        match validate_sec_fetch_site(&h) {
            Err(ApiError::Forbidden(Some(msg))) => {
                assert!(msg.contains("Invalid Sec-Fetch-Site"));
            }
            other => panic!("expected Forbidden with message, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    #[test]
    fn test_sec_fetch_site_empty_string_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "");
        // Empty string does not match any allowed value.
        let result = validate_sec_fetch_site(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_site_same_site_case_insensitive() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "SAME-SITE");
        assert!(validate_sec_fetch_site(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_site_none_case_insensitive() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "None");
        assert!(validate_sec_fetch_site(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_site_whitespace_not_trimmed() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", " same-origin ");
        // Leading/trailing whitespace makes it an invalid value.
        let result = validate_sec_fetch_site(&h);
        assert!(result.is_err());
    }

    // ── Additional Sec-Fetch-Mode tests ───────────────────────────────

    #[test]
    fn test_sec_fetch_mode_empty_string_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "");
        let result = validate_sec_fetch_mode(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_mode_same_origin_case_insensitive() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "SAME-ORIGIN");
        assert!(validate_sec_fetch_mode(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_mode_navigate_case_insensitive() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "Navigate");
        let result = validate_sec_fetch_mode(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_mode_no_cors_case_insensitive() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "NO-CORS");
        let result = validate_sec_fetch_mode(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_mode_websocket_case_insensitive() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "WEBSOCKET");
        let result = validate_sec_fetch_mode(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_mode_invalid_value_error_message() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "invalid");
        match validate_sec_fetch_mode(&h) {
            Err(ApiError::Forbidden(Some(msg))) => {
                assert!(msg.contains("Invalid Sec-Fetch-Mode"));
            }
            other => panic!("expected Forbidden with message, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    // ── Additional Sec-Fetch-Dest tests ───────────────────────────────

    #[test]
    fn test_sec_fetch_dest_empty_string_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "");
        // Empty string header value: not the same as "empty" the keyword.
        let result = validate_sec_fetch_dest(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_dest_document_case_insensitive() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "DOCUMENT");
        assert!(validate_sec_fetch_dest(&h).is_ok());
    }

    #[test]
    fn test_sec_fetch_dest_font_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "font");
        let result = validate_sec_fetch_dest(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_dest_audio_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "audio");
        let result = validate_sec_fetch_dest(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_dest_video_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "video");
        let result = validate_sec_fetch_dest(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_dest_object_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "object");
        let result = validate_sec_fetch_dest(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_dest_worker_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "worker");
        let result = validate_sec_fetch_dest(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_fetch_dest_error_message() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "image");
        match validate_sec_fetch_dest(&h) {
            Err(ApiError::Forbidden(Some(msg))) => {
                assert!(msg.contains("Unexpected Sec-Fetch-Dest"));
            }
            other => panic!("expected Forbidden with message, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    // ── Additional combined validation tests ──────────────────────────

    #[test]
    fn test_validate_fetch_metadata_partial_headers_site_only() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        // Mode and Dest missing: allowed (non-browser client).
        assert!(validate_fetch_metadata(&h).is_ok());
    }

    #[test]
    fn test_validate_fetch_metadata_partial_headers_mode_only() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Mode", "cors");
        // Site missing: allowed. Mode valid. Dest missing: allowed.
        assert!(validate_fetch_metadata(&h).is_ok());
    }

    #[test]
    fn test_validate_fetch_metadata_partial_headers_dest_only() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Dest", "empty");
        assert!(validate_fetch_metadata(&h).is_ok());
    }

    #[test]
    fn test_validate_fetch_metadata_site_and_mode_valid_dest_missing() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "cors");
        assert!(validate_fetch_metadata(&h).is_ok());
    }

    #[test]
    fn test_validate_fetch_metadata_mode_fails_preserves_error_type() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "no-cors");
        match validate_fetch_metadata(&h) {
            Err(ApiError::Forbidden(Some(msg))) => {
                assert!(msg.contains("no-cors"));
            }
            other => panic!("expected Forbidden, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    // ── Additional CSP-variant tests ──────────────────────────────────

    #[test]
    fn test_validate_fetch_metadata_csp_cors_and_same_origin_modes_pass() {
        for mode in &["cors", "same-origin", "no-cors"] {
            let mut h = TestHeaders::new();
            h.set("Sec-Fetch-Site", "same-origin");
            h.set("Sec-Fetch-Mode", mode);
            h.set("Sec-Fetch-Dest", "empty");
            assert!(
                validate_fetch_metadata_csp(&h).is_ok(),
                "CSP variant should allow mode '{}'",
                mode
            );
        }
    }

    #[test]
    fn test_validate_fetch_metadata_csp_invalid_mode_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "weird-mode");
        h.set("Sec-Fetch-Dest", "empty");
        let result = validate_fetch_metadata_csp(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_fetch_metadata_csp_site_cross_site_still_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "cross-site");
        h.set("Sec-Fetch-Mode", "no-cors");
        h.set("Sec-Fetch-Dest", "empty");
        // CSP variant allows no-cors mode, but cross-site is still rejected.
        let result = validate_fetch_metadata_csp(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_fetch_metadata_csp_dest_image_rejected() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "no-cors");
        h.set("Sec-Fetch-Dest", "image");
        let result = validate_fetch_metadata_csp(&h);
        assert!(result.is_err());
    }

    // ── Additional strict-mode tests ──────────────────────────────────

    #[test]
    fn test_validate_fetch_metadata_strict_case_insensitive_site() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "SAME-ORIGIN");
        h.set("Sec-Fetch-Mode", "cors");
        h.set("Sec-Fetch-Dest", "empty");
        assert!(validate_fetch_metadata_strict(&h).is_ok());
    }

    #[test]
    fn test_validate_fetch_metadata_strict_invalid_site_returns_not_found() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "bogus");
        h.set("Sec-Fetch-Mode", "cors");
        h.set("Sec-Fetch-Dest", "empty");
        match validate_fetch_metadata_strict(&h) {
            Err(ApiError::NotFound) => {}
            other => panic!("expected NotFound, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    #[test]
    fn test_validate_fetch_metadata_strict_all_missing_rejects() {
        let h = TestHeaders::new();
        // Strict mode requires Sec-Fetch-Site.
        match validate_fetch_metadata_strict(&h) {
            Err(ApiError::NotFound) => {}
            other => panic!("expected NotFound, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    #[test]
    fn test_validate_fetch_metadata_strict_navigate_mode_returns_not_found() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "navigate");
        h.set("Sec-Fetch-Dest", "empty");
        match validate_fetch_metadata_strict(&h) {
            Err(ApiError::NotFound) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "expected NotFound for navigate mode in strict, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_validate_fetch_metadata_strict_no_cors_mode_returns_not_found() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "no-cors");
        h.set("Sec-Fetch-Dest", "empty");
        match validate_fetch_metadata_strict(&h) {
            Err(ApiError::NotFound) => {}
            other => panic!("expected NotFound for no-cors in strict, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    #[test]
    fn test_validate_fetch_metadata_strict_with_document_dest() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        h.set("Sec-Fetch-Mode", "same-origin");
        h.set("Sec-Fetch-Dest", "document");
        assert!(validate_fetch_metadata_strict(&h).is_ok());
    }

    #[test]
    fn test_validate_fetch_metadata_strict_missing_mode_and_dest_passes() {
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "same-origin");
        // Mode and Dest missing: standard validation allows missing headers.
        assert!(validate_fetch_metadata_strict(&h).is_ok());
    }

    // ── Error variant classification tests ────────────────────────────

    #[test]
    fn test_standard_rejection_returns_forbidden() {
        // All standard validators return Forbidden, not NotFound.
        let mut h = TestHeaders::new();
        h.set("Sec-Fetch-Site", "cross-site");
        match validate_sec_fetch_site(&h) {
            Err(ApiError::Forbidden(_)) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "standard site rejection should be Forbidden, got {:?}",
                other
            ),
        }

        let mut h2 = TestHeaders::new();
        h2.set("Sec-Fetch-Mode", "websocket");
        match validate_sec_fetch_mode(&h2) {
            Err(ApiError::Forbidden(_)) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "standard mode rejection should be Forbidden, got {:?}",
                other
            ),
        }

        let mut h3 = TestHeaders::new();
        h3.set("Sec-Fetch-Dest", "script");
        match validate_sec_fetch_dest(&h3) {
            Err(ApiError::Forbidden(_)) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "standard dest rejection should be Forbidden, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_strict_rejection_always_returns_not_found() {
        // Strict mode maps all rejections to NotFound to hide endpoint existence.
        let scenarios: Vec<(&str, &str, &str)> = vec![
            ("cross-site", "cors", "empty"),
            ("same-origin", "websocket", "empty"),
            ("same-origin", "cors", "script"),
            ("bogus", "cors", "empty"),
        ];
        for (site, mode, dest) in scenarios {
            let mut h = TestHeaders::new();
            h.set("Sec-Fetch-Site", site);
            h.set("Sec-Fetch-Mode", mode);
            h.set("Sec-Fetch-Dest", dest);
            match validate_fetch_metadata_strict(&h) {
                Err(ApiError::NotFound) => {}
                // nosemgrep: provii.workers.panic-in-worker
                other => panic!(
                    "strict({},{},{}) should return NotFound, got {:?}",
                    site, mode, dest, other
                ),
            }
        }
    }
}
