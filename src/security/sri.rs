// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Subresource Integrity (SRI) helper functions.
//!
//! Provides utilities for generating HTML tags with SRI integrity attributes to
//! prevent supply chain attacks via compromised CDN assets. Implements ASVS V3.6.1.
#![forbid(unsafe_code)]

/// Known CDN assets with their pre-computed SHA-384 integrity hashes.
///
/// These hashes are generated using:
/// ```bash
/// curl -sS &lt;URL&gt; | openssl dgst -sha384 -binary | openssl base64 -A
/// ```
pub mod known_assets {
    /// Swagger UI CSS (pinned to exact version for SRI hash stability).
    /// CH-020: Version pinned to prevent silent breakage when CDN updates.
    /// If bumping the version, recompute the SRI hash:
    ///   curl -sS &lt;URL&gt; | openssl dgst -sha384 -binary | openssl base64 -A
    pub const SWAGGER_UI_CSS_URL: &str =
        "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.18.2/swagger-ui.css";
    /// SHA-384 SRI hash for [`SWAGGER_UI_CSS_URL`].
    pub const SWAGGER_UI_CSS_INTEGRITY: &str =
        "sha384-++DMKo1369T5pxDNqojF1F91bYxYiT1N7b1M15a7oCzEodfljztKlApQoH6eQSKI";

    /// Swagger UI JavaScript bundle (pinned to exact version for SRI hash stability).
    pub const SWAGGER_UI_JS_URL: &str =
        "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.18.2/swagger-ui-bundle.js";
    /// SHA-384 SRI hash for [`SWAGGER_UI_JS_URL`].
    pub const SWAGGER_UI_JS_INTEGRITY: &str =
        "sha384-bBdB196maIUakX6v2F6J0XcjddQfaENm8kASsYfqTKCZua9xlYNh1AdtL18PGr0D";
}

/// Generate a `<script>` tag with SRI integrity attribute and crossorigin.
///
/// # Arguments
/// * `url` - The CDN URL for the script
/// * `integrity` - The SRI hash (format: "sha384-BASE64HASH")
///
/// # Returns
/// A complete script tag string with integrity and crossorigin attributes.
///
/// # Example
/// ```
/// use provii_verifier::security::sri::script_tag_with_sri;
///
/// let tag = script_tag_with_sri(
///     "https://cdn.example.com/lib.js",
///     "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/ux..."
/// );
/// assert!(tag.contains("integrity="));
/// assert!(tag.contains("crossorigin=\"anonymous\""));
/// ```
pub fn script_tag_with_sri(url: &str, integrity: &str) -> String {
    format!(
        r#"<script src="{}" integrity="{}" crossorigin="anonymous"></script>"#,
        url, integrity
    )
}

/// Generate a `<link>` stylesheet tag with SRI integrity attribute and crossorigin.
///
/// # Arguments
/// * `url` - The CDN URL for the stylesheet
/// * `integrity` - The SRI hash (format: "sha384-BASE64HASH")
///
/// # Returns
/// A complete link tag string with integrity and crossorigin attributes.
///
/// # Example
/// ```
/// use provii_verifier::security::sri::link_stylesheet_with_sri;
///
/// let tag = link_stylesheet_with_sri(
///     "https://cdn.example.com/style.css",
///     "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/ux..."
/// );
/// assert!(tag.contains("integrity="));
/// assert!(tag.contains("crossorigin=\"anonymous\""));
/// ```
pub fn link_stylesheet_with_sri(url: &str, integrity: &str) -> String {
    format!(
        r#"<link rel="stylesheet" href="{}" integrity="{}" crossorigin="anonymous">"#,
        url, integrity
    )
}

/// Generate the complete Swagger UI HTML with SRI-protected CDN assets and CSP nonce.
///
/// Creates a self-contained HTML document for Swagger UI that includes SRI
/// integrity hashes on all external CDN resources and a CSP nonce for inline
/// scripts to avoid `unsafe-inline`.
///
/// # Arguments
/// * `openapi_json_url` - The URL to the OpenAPI JSON specification
/// * `nonce` - CSP nonce for the inline script (must match the nonce in the CSP header)
///
/// # Returns
/// A complete HTML document string with SRI-protected assets and nonce-protected inline scripts.
///
/// # Security
///
/// SECURITY (CH-022): The `openapi_json_url` is escaped for safe interpolation
/// inside a JS string literal to prevent XSS if the URL ever contains
/// attacker-controlled characters.
///
/// All CDN assets include SHA-384 integrity hashes to detect tampering, plus
/// `crossorigin="anonymous"` for proper CORS validation. Inline scripts use a
/// CSP nonce instead of `unsafe-inline` (ASVS V2.2.3, V3.6.1).
pub fn generate_swagger_ui_html(openapi_json_url: &str, nonce: &str) -> String {
    // CH-022: Escape the URL for safe interpolation inside a JS string literal.
    // This prevents XSS if the URL ever contains attacker-controlled characters.
    let escaped_url = openapi_json_url
        .replace('&', "\\x26")
        .replace('<', "\\x3c")
        .replace('>', "\\x3e")
        .replace('"', "\\x22")
        .replace('\'', "\\x27");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ZeroKP API Documentation</title>
    {}
</head>
<body>
    <div id="swagger-ui"></div>
    {}
    <script nonce="{}">
        window.onload = function() {{
            SwaggerUIBundle({{
                url: "{}",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [SwaggerUIBundle.presets.apis],
                layout: "BaseLayout"
            }});
        }};
    </script>
</body>
</html>"#,
        link_stylesheet_with_sri(
            known_assets::SWAGGER_UI_CSS_URL,
            known_assets::SWAGGER_UI_CSS_INTEGRITY
        ),
        script_tag_with_sri(
            known_assets::SWAGGER_UI_JS_URL,
            known_assets::SWAGGER_UI_JS_INTEGRITY
        ),
        nonce,
        escaped_url
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_tag_with_sri_basic() {
        let tag = script_tag_with_sri("https://example.com/script.js", "sha384-abc123");
        assert!(tag.starts_with("<script "));
        assert!(tag.ends_with("</script>"));
        assert!(tag.contains(r#"src="https://example.com/script.js""#));
        assert!(tag.contains(r#"integrity="sha384-abc123""#));
        assert!(tag.contains(r#"crossorigin="anonymous""#));
    }

    #[test]
    fn test_script_tag_with_sri_order() {
        let tag = script_tag_with_sri("https://cdn.example.com/lib.js", "sha384-xyz789");
        // Verify attributes are present (order doesn't matter in HTML)
        assert!(tag.contains("src="));
        assert!(tag.contains("integrity="));
        assert!(tag.contains("crossorigin="));
    }

    #[test]
    fn test_script_tag_with_sri_quoting() {
        let tag = script_tag_with_sri("https://example.com/app.js", "sha384-test");
        // Ensure proper double-quote usage
        assert!(tag.contains(r#"src="https://example.com/app.js""#));
        assert!(tag.contains(r#"integrity="sha384-test""#));
        assert!(tag.contains(r#"crossorigin="anonymous""#));
    }

    #[test]
    fn test_link_stylesheet_with_sri_basic() {
        let tag = link_stylesheet_with_sri("https://example.com/style.css", "sha384-def456");
        assert!(tag.starts_with("<link "));
        assert!(tag.ends_with(">"));
        assert!(tag.contains(r#"rel="stylesheet""#));
        assert!(tag.contains(r#"href="https://example.com/style.css""#));
        assert!(tag.contains(r#"integrity="sha384-def456""#));
        assert!(tag.contains(r#"crossorigin="anonymous""#));
    }

    #[test]
    fn test_link_stylesheet_with_sri_attributes() {
        let tag = link_stylesheet_with_sri("https://cdn.example.com/theme.css", "sha384-uvw456");
        assert!(tag.contains("rel="));
        assert!(tag.contains("href="));
        assert!(tag.contains("integrity="));
        assert!(tag.contains("crossorigin="));
    }

    #[test]
    fn test_swagger_ui_html_structure() {
        let html = generate_swagger_ui_html("/api/openapi.json", "test-nonce-123");
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<html lang=\"en\">"));
        assert!(html.contains("<head>"));
        assert!(html.contains("<body>"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn test_swagger_ui_html_contains_css_with_sri() {
        let html = generate_swagger_ui_html("/api/openapi.json", "test-nonce-123");
        assert!(html.contains(known_assets::SWAGGER_UI_CSS_URL));
        assert!(html.contains(known_assets::SWAGGER_UI_CSS_INTEGRITY));
        assert!(html.contains("crossorigin=\"anonymous\""));
    }

    #[test]
    fn test_swagger_ui_html_contains_js_with_sri() {
        let html = generate_swagger_ui_html("/api/openapi.json", "test-nonce-123");
        assert!(html.contains(known_assets::SWAGGER_UI_JS_URL));
        assert!(html.contains(known_assets::SWAGGER_UI_JS_INTEGRITY));
    }

    #[test]
    fn test_swagger_ui_html_openapi_url() {
        let html = generate_swagger_ui_html("/v1/openapi.json", "test-nonce-456");
        assert!(html.contains(r#"url: "/v1/openapi.json""#));
    }

    #[test]
    fn test_swagger_ui_html_custom_openapi_url() {
        let html = generate_swagger_ui_html("/custom/api-spec.json", "test-nonce-789");
        assert!(html.contains(r#"url: "/custom/api-spec.json""#));
    }

    #[test]
    fn test_swagger_ui_html_has_swagger_ui_div() {
        let html = generate_swagger_ui_html("/api.json", "test-nonce-abc");
        assert!(html.contains(r#"<div id="swagger-ui"></div>"#));
    }

    #[test]
    fn test_swagger_ui_html_has_initialization_script() {
        let html = generate_swagger_ui_html("/api.json", "test-nonce-def");
        assert!(html.contains("window.onload = function()"));
        assert!(html.contains("SwaggerUIBundle({"));
        assert!(html.contains("deepLinking: true"));
    }

    // ADV-VA-06-007: Removed spurious wasm32 gate. generate_swagger_ui_html
    // is a pure function with no worker runtime dependency.
    #[test]
    fn test_swagger_ui_html_has_nonce_attribute() {
        let nonce = "test-nonce-ghi";
        let html = generate_swagger_ui_html("/api.json", nonce);
        // Inline script should have nonce attribute instead of integrity
        let nonce_tag = format!(r#"<script nonce="{}">"#, nonce);
        assert!(html.contains(&nonce_tag));
        // The inline (nonce-bearing) script tag must NOT also carry an
        // integrity attribute. External CDN tags do carry integrity, which
        // is correct.
        let inline_block = html.split(&nonce_tag).nth(1).expect("nonce tag present");
        let inline_script = inline_block.split("</script>").next().unwrap_or("");
        assert!(
            !inline_script.contains("integrity="),
            "inline nonce script must not carry an integrity attribute"
        );
    }

    #[test]
    fn test_known_assets_swagger_css_url() {
        assert_eq!(
            known_assets::SWAGGER_UI_CSS_URL,
            "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.18.2/swagger-ui.css"
        );
    }

    #[test]
    fn test_known_assets_swagger_css_integrity_format() {
        assert!(known_assets::SWAGGER_UI_CSS_INTEGRITY.starts_with("sha384-"));
        assert!(known_assets::SWAGGER_UI_CSS_INTEGRITY.len() > 50); // SHA-384 base64 is 64 chars + prefix
    }

    #[test]
    fn test_known_assets_swagger_js_url() {
        assert_eq!(
            known_assets::SWAGGER_UI_JS_URL,
            "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.18.2/swagger-ui-bundle.js"
        );
    }

    #[test]
    fn test_known_assets_swagger_js_integrity_format() {
        assert!(known_assets::SWAGGER_UI_JS_INTEGRITY.starts_with("sha384-"));
        assert!(known_assets::SWAGGER_UI_JS_INTEGRITY.len() > 50);
    }

    #[test]
    fn test_script_tag_empty_url() {
        let tag = script_tag_with_sri("", "sha384-test");
        assert!(tag.contains(r#"src="""#));
    }

    #[test]
    fn test_link_tag_empty_url() {
        let tag = link_stylesheet_with_sri("", "sha384-test");
        assert!(tag.contains(r#"href="""#));
    }

    #[test]
    fn test_generate_swagger_ui_html_encoding() {
        let html = generate_swagger_ui_html("/api.json", "test-nonce-jkl");
        // Ensure proper HTML structure (not double-encoded)
        assert!(html.contains("<script"));
        assert!(html.contains("<link"));
        assert!(!html.contains("&lt;script"));
        assert!(!html.contains("&lt;link"));
    }

    #[test]
    fn test_swagger_ui_html_title() {
        let html = generate_swagger_ui_html("/api.json", "test-nonce-mno");
        assert!(html.contains("<title>ZeroKP API Documentation</title>"));
    }

    #[test]
    fn test_swagger_ui_html_charset() {
        let html = generate_swagger_ui_html("/api.json", "test-nonce-pqr");
        assert!(html.contains(r#"<meta charset="UTF-8">"#));
    }

    /* ========================================================================== */
    /*                    XSS ESCAPE TESTS (CH-022)                              */
    /* ========================================================================== */

    #[test]
    fn test_swagger_ui_html_escapes_ampersand_in_url() {
        let html = generate_swagger_ui_html("/api.json?a=1&b=2", "nonce-esc");
        assert!(html.contains("\\x26"));
        assert!(!html.contains("url: \"/api.json?a=1&b=2\""));
    }

    #[test]
    fn test_swagger_ui_html_escapes_angle_brackets_in_url() {
        let html = generate_swagger_ui_html("/api.json?x=<script>", "nonce-esc");
        assert!(html.contains("\\x3c"));
        assert!(html.contains("\\x3e"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn test_swagger_ui_html_escapes_double_quote_in_url() {
        let html = generate_swagger_ui_html("/api.json?x=\"bad\"", "nonce-esc");
        assert!(html.contains("\\x22"));
    }

    #[test]
    fn test_swagger_ui_html_escapes_single_quote_in_url() {
        let html = generate_swagger_ui_html("/api.json?x='bad'", "nonce-esc");
        assert!(html.contains("\\x27"));
    }

    #[test]
    fn test_swagger_ui_html_escapes_all_dangerous_chars() {
        let html = generate_swagger_ui_html("<>&\"'", "nonce-all");
        // All five characters replaced
        assert!(html.contains("\\x3c"));
        assert!(html.contains("\\x3e"));
        assert!(html.contains("\\x26"));
        assert!(html.contains("\\x22"));
        assert!(html.contains("\\x27"));
    }

    #[test]
    fn test_swagger_ui_html_safe_url_unchanged() {
        let url = "/v1/openapi.json";
        let html = generate_swagger_ui_html(url, "nonce-safe");
        assert!(html.contains(&format!("url: \"{}\"", url)));
    }

    /* ========================================================================== */
    /*                    NONCE TESTS                                            */
    /* ========================================================================== */

    #[test]
    fn test_swagger_ui_html_nonce_in_script_tag() {
        let nonce = "abc123nonce";
        let html = generate_swagger_ui_html("/api.json", nonce);
        assert!(html.contains(&format!("<script nonce=\"{}\">", nonce)));
    }

    #[test]
    fn test_swagger_ui_html_empty_nonce() {
        let html = generate_swagger_ui_html("/api.json", "");
        assert!(html.contains("<script nonce=\"\">"));
    }

    /* ========================================================================== */
    /*                    ASSET ORDERING AND STRUCTURE TESTS                     */
    /* ========================================================================== */

    #[test]
    fn test_swagger_ui_css_before_js_in_html() {
        let html = generate_swagger_ui_html("/api.json", "nonce-order");
        let css_pos = html
            .find(known_assets::SWAGGER_UI_CSS_URL)
            .expect("CSS URL must be present");
        let js_pos = html
            .find(known_assets::SWAGGER_UI_JS_URL)
            .expect("JS URL must be present");
        assert!(
            css_pos < js_pos,
            "CSS must appear before JS in the HTML document"
        );
    }

    #[test]
    fn test_swagger_ui_css_in_head_js_in_body() {
        let html = generate_swagger_ui_html("/api.json", "nonce-loc");
        let head_end = html.find("</head>").expect("</head> must be present");
        let body_start = html.find("<body>").expect("<body> must be present");

        let css_pos = html
            .find(known_assets::SWAGGER_UI_CSS_URL)
            .expect("CSS URL must be present");
        let js_pos = html
            .find(known_assets::SWAGGER_UI_JS_URL)
            .expect("JS URL must be present");

        assert!(css_pos < head_end, "CSS link must be in <head>");
        assert!(js_pos > body_start, "JS script must be in <body>");
    }

    #[test]
    fn test_swagger_ui_html_layout_config() {
        let html = generate_swagger_ui_html("/api.json", "nonce-layout");
        assert!(html.contains("dom_id: '#swagger-ui'"));
        assert!(html.contains("layout: \"BaseLayout\""));
        assert!(html.contains("presets: [SwaggerUIBundle.presets.apis]"));
    }

    /* ========================================================================== */
    /*                    TAG GENERATION EDGE CASES                              */
    /* ========================================================================== */

    #[test]
    fn test_script_tag_with_special_chars_in_integrity() {
        // Base64 can contain +, /, = which should pass through
        let tag = script_tag_with_sri("https://cdn.example.com/lib.js", "sha384-abc+def/ghi=");
        assert!(tag.contains("integrity=\"sha384-abc+def/ghi=\""));
    }

    #[test]
    fn test_link_stylesheet_with_special_chars_in_integrity() {
        let tag = link_stylesheet_with_sri("https://cdn.example.com/s.css", "sha384-a+b/c=");
        assert!(tag.contains("integrity=\"sha384-a+b/c=\""));
    }

    #[test]
    fn test_script_tag_empty_integrity() {
        let tag = script_tag_with_sri("https://cdn.example.com/lib.js", "");
        assert!(tag.contains("integrity=\"\""));
    }

    #[test]
    fn test_link_stylesheet_empty_integrity() {
        let tag = link_stylesheet_with_sri("https://cdn.example.com/s.css", "");
        assert!(tag.contains("integrity=\"\""));
    }

    #[test]
    fn test_script_tag_no_self_closing() {
        // Script tags must NOT be self-closing in HTML5
        let tag = script_tag_with_sri("https://example.com/s.js", "sha384-x");
        assert!(!tag.contains("/>"));
        assert!(tag.ends_with("</script>"));
    }

    #[test]
    fn test_link_stylesheet_is_void_element() {
        // Link tags are void elements, no closing tag
        let tag = link_stylesheet_with_sri("https://example.com/s.css", "sha384-x");
        assert!(!tag.contains("</link>"));
        assert!(tag.ends_with(">"));
    }

    /* ========================================================================== */
    /*                    KNOWN ASSET INTEGRITY TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_known_assets_css_and_js_are_same_version() {
        // Both CSS and JS URLs must pin the same Swagger UI version
        let css_version = known_assets::SWAGGER_UI_CSS_URL
            .split('@')
            .nth(1)
            .and_then(|s| s.split('/').next());
        let js_version = known_assets::SWAGGER_UI_JS_URL
            .split('@')
            .nth(1)
            .and_then(|s| s.split('/').next());
        assert_eq!(css_version, js_version);
    }

    #[test]
    fn test_known_assets_urls_use_https() {
        assert!(known_assets::SWAGGER_UI_CSS_URL.starts_with("https://"));
        assert!(known_assets::SWAGGER_UI_JS_URL.starts_with("https://"));
    }

    #[test]
    fn test_known_assets_integrity_hashes_are_sha384() {
        assert!(known_assets::SWAGGER_UI_CSS_INTEGRITY.starts_with("sha384-"));
        assert!(known_assets::SWAGGER_UI_JS_INTEGRITY.starts_with("sha384-"));
    }

    #[test]
    fn test_known_assets_css_and_js_integrity_differ() {
        // CSS and JS are different files, so their hashes must differ
        assert_ne!(
            known_assets::SWAGGER_UI_CSS_INTEGRITY,
            known_assets::SWAGGER_UI_JS_INTEGRITY
        );
    }

    // ========================================================================
    // Edge case tests: null bytes, max-length, unicode
    // ========================================================================

    #[test]
    fn test_script_tag_url_with_null_byte() {
        let tag = script_tag_with_sri("https://cdn.example.com/\0script.js", "sha384-abc");
        assert!(tag.contains("src=\"https://cdn.example.com/\0script.js\""));
    }

    #[test]
    fn test_link_tag_url_with_null_byte() {
        let tag = link_stylesheet_with_sri("https://cdn.example.com/\0style.css", "sha384-abc");
        assert!(tag.contains("href=\"https://cdn.example.com/\0style.css\""));
    }

    #[test]
    fn test_script_tag_with_very_long_url() {
        let long_path = "a".repeat(10_000);
        let url = format!("https://cdn.example.com/{}", long_path);
        let tag = script_tag_with_sri(&url, "sha384-test");
        assert!(tag.contains(&url));
        assert!(tag.len() > 10_000);
    }

    #[test]
    fn test_link_tag_with_very_long_integrity() {
        let long_hash = "x".repeat(10_000);
        let integrity = format!("sha384-{}", long_hash);
        let tag = link_stylesheet_with_sri("https://cdn.example.com/s.css", &integrity);
        assert!(tag.contains(&integrity));
    }

    #[test]
    fn test_swagger_ui_html_with_unicode_url() {
        let html = generate_swagger_ui_html("/api/\u{00e9}ndpoint.json", "nonce-uni");
        // The e-acute should pass through unescaped (not in the escape set)
        assert!(html.contains("\u{00e9}ndpoint"));
    }

    #[test]
    fn test_swagger_ui_html_with_very_long_nonce() {
        let long_nonce = "n".repeat(1_000);
        let html = generate_swagger_ui_html("/api.json", &long_nonce);
        assert!(html.contains(&long_nonce));
    }
}
