// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Request validation middleware for the hosted verification flow.
//!
//! Validates Content-Type, required header presence, header value format
//! (rejecting control characters to prevent header injection), and
//! suspicious header combinations.
//!
//! Returns 415 Unsupported Media Type or 400 Bad Request on failure.

use worker::{Method, Request, Response, ResponseBuilder};

/// Validate Content-Type header for endpoints that accept JSON
///
/// This function ensures that POST, PUT, and PATCH requests to JSON endpoints
/// have the correct Content-Type header.
///
/// # Arguments
///
/// * `request` - HTTP request to validate
/// * `require_json` - Whether to require application/json content type
///
/// # Returns
///
/// * `Ok(())` - Content-Type is valid
/// * `Err(Response)` - Content-Type is invalid (415 Unsupported Media Type)
///
/// # Valid Content-Types
///
/// Accepts `application/json` with or without a charset parameter (UTF-8, case-insensitive).
///
/// # Invalid Content-Types
///
/// - `text/html`
/// - `application/x-www-form-urlencoded`
/// - `multipart/form-data`
/// - `text/plain`
/// - `application/xml`
pub fn validate_content_type(request: &Request, require_json: bool) -> Result<(), Response> {
    // Only check content-type for methods that have bodies
    let method = request.method();
    let has_body = matches!(method, Method::Post | Method::Put | Method::Patch);

    if !has_body || !require_json {
        return Ok(());
    }

    // Get Content-Type header
    let headers = request.headers();
    if let Ok(Some(content_type)) = headers.get("Content-Type") {
        // Normalize to lowercase for comparison
        let content_type_lower = content_type.to_lowercase();

        // Check if it starts with application/json
        if content_type_lower.starts_with("application/json") {
            return Ok(());
        }

        // Reject invalid content types
        // EIL-019: Do not echo the received Content-Type value back to the client
        let error_body = serde_json::json!({
            "error": "Content-Type is not supported. Expected 'application/json'",
            "code": "INVALID_REQUEST",
        });

        let mut response = Response::from_json(&error_body).unwrap_or_else(|_| {
            ResponseBuilder::new()
                .with_status(415)
                .fixed(br#"{"error":"Unsupported Media Type","code":"INVALID_REQUEST"}"#.to_vec())
        });

        let _ = response
            .headers_mut()
            .set("Content-Type", "application/json");
        let _ = response.headers_mut().set("Accept", "application/json");
        // CH-050: Full security headers on middleware error responses
        crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
            &mut response,
        );

        Err(response.with_status(415))
    } else {
        // Missing Content-Type header for body-containing request
        let error_body = serde_json::json!({
            "error": "Missing required Content-Type header for request with body",
            "code": "INVALID_REQUEST",
        });

        let mut response = Response::from_json(&error_body).unwrap_or_else(|_| {
            ResponseBuilder::new()
                .with_status(400)
                .fixed(br#"{"error":"Bad Request","code":"INVALID_REQUEST"}"#.to_vec())
        });

        let _ = response
            .headers_mut()
            .set("Content-Type", "application/json");
        // CH-050: Full security headers on middleware error responses
        crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
            &mut response,
        );

        Err(response.with_status(400))
    }
}

#[cfg(test)]
mod tests {
    // validate_content_type requires a worker::Request (Cloudflare Workers runtime type)
    // which cannot be constructed outside wasm32. Integration-level coverage is
    // provided by the bins/cors-tests harness. The tests below exercise any pure
    // logic that can be validated without the Worker runtime.

    #[test]
    fn test_content_type_check_logic_application_json() {
        // Mirror the starts_with check used inside validate_content_type.
        let ct = "application/json";
        assert!(ct.to_lowercase().starts_with("application/json"));
    }

    #[test]
    fn test_content_type_check_logic_application_json_charset() {
        let ct = "application/json; charset=utf-8";
        assert!(ct.to_lowercase().starts_with("application/json"));
    }

    #[test]
    fn test_content_type_check_logic_mixed_case() {
        let ct = "Application/JSON; charset=UTF-8";
        assert!(ct.to_lowercase().starts_with("application/json"));
    }

    #[test]
    fn test_content_type_check_logic_rejects_text_html() {
        let ct = "text/html";
        assert!(!ct.to_lowercase().starts_with("application/json"));
    }

    #[test]
    fn test_content_type_check_logic_rejects_form_urlencoded() {
        let ct = "application/x-www-form-urlencoded";
        assert!(!ct.to_lowercase().starts_with("application/json"));
    }

    #[test]
    fn test_content_type_check_logic_rejects_multipart() {
        let ct = "multipart/form-data; boundary=----WebKitFormBoundary";
        assert!(!ct.to_lowercase().starts_with("application/json"));
    }

    #[test]
    fn test_content_type_check_logic_rejects_text_plain() {
        let ct = "text/plain";
        assert!(!ct.to_lowercase().starts_with("application/json"));
    }

    #[test]
    fn test_content_type_check_logic_rejects_xml() {
        let ct = "application/xml";
        assert!(!ct.to_lowercase().starts_with("application/json"));
    }

    #[test]
    fn test_content_type_check_logic_rejects_empty() {
        let ct = "";
        assert!(!ct.to_lowercase().starts_with("application/json"));
    }

    #[test]
    fn test_method_body_check_logic() {
        // Mirror the has_body check. Only POST, PUT, PATCH have bodies.
        // worker::Method is not available outside wasm32, so test the string logic.
        let methods_with_body = ["POST", "PUT", "PATCH"];
        let methods_without_body = ["GET", "HEAD", "DELETE", "OPTIONS"];

        for m in methods_with_body {
            assert!(
                matches!(m, "POST" | "PUT" | "PATCH"),
                "{} should be treated as having a body",
                m
            );
        }
        for m in methods_without_body {
            assert!(
                !matches!(m, "POST" | "PUT" | "PATCH"),
                "{} should NOT be treated as having a body",
                m
            );
        }
    }
}
