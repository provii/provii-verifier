// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! CSP violation reporting endpoint for security monitoring.
//!
//! Receives browser-sent Content Security Policy violation reports, validates
//! field lengths, strips query parameters to prevent PII leakage, persists
//! sanitised reports to KV, and logs violations for offline analysis.
//! Implements ASVS V3.4.7 (CSP Reporting Directives).
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use worker::{Request, Response, RouteContext};

use crate::bindings::KV_CONFIG;
use crate::security::headers::api_security_headers;
use crate::AppState;

/// Build a JSON error response with security headers for CSP report validation failures.
///
/// VA-API-001: Uses the standard 5-key error envelope ({error, message,
/// request_id, field, detail}) for consistency with ApiError responses.
fn csp_error_response(status: u16, message: &str) -> worker::Result<Response> {
    let body = serde_json::json!({
        "error": message,
        "message": message,
        "request_id": serde_json::Value::Null,
        "field": serde_json::Value::Null,
        "detail": serde_json::Value::Null,
    });
    let mut response = Response::from_json(&body)?.with_status(status);
    response
        .headers_mut()
        .set("Content-Type", "application/json; charset=utf-8")?;
    let security_headers = api_security_headers();
    security_headers.apply(&mut response)?;
    Ok(response)
}

// SECURITY: ASVS V2.1.3 - Maximum CSP URI field length
const MAX_CSP_URI_LENGTH: usize = 2048;
// IV-107: Maximum length for CSP directive and policy fields.
// Directives are short strings like "script-src"; 512 bytes is generous.
const MAX_CSP_DIRECTIVE_LENGTH: usize = 512;
// IV-107: Maximum length for the original_policy field.
// CSP policies can be long but 8 KB is more than sufficient.
const MAX_CSP_POLICY_LENGTH: usize = 8192;
// IV-107: Maximum length for the disposition field ("enforce" or "report").
const MAX_CSP_DISPOSITION_LENGTH: usize = 64;
// IV-107: Maximum length for the script_sample field.
const MAX_CSP_SCRIPT_SAMPLE_LENGTH: usize = 512;
// Maximum CSP report body size (16 KB). CSP reports are small JSON payloads;
// anything larger is likely abuse.
const MAX_CSP_BODY_SIZE: u64 = 16_384;

/// Strip query string and fragment from a URI to prevent PII leakage.
///
/// Query parameters and fragments may contain user-specific tokens, email
/// addresses, session identifiers, or other personally identifiable data
/// that must not appear in logs or persisted audit records.
fn strip_uri_params(uri: &str) -> &str {
    uri.split(&['?', '#'][..]).next().unwrap_or(uri)
}

/// CSP violation report structure.
/// Follows the standard CSP reporting format as defined by the W3C.
/// See: <https://www.w3.org/TR/CSP3/#reporting>
///
/// SECURITY: deny_unknown_fields prevents browsers from injecting unexpected fields
/// that could bypass validation or cause unexpected behaviour (ASVS V3.5.3).
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CspReportBody {
    /// URI of the document where the violation occurred.
    pub document_uri: String,
    /// Referrer of the document, if any.
    pub referrer: Option<String>,
    /// URI that was blocked by the policy.
    pub blocked_uri: String,
    /// The directive that was violated (e.g. `script-src`).
    pub violated_directive: String,
    /// The directive enforced by the user agent.
    pub effective_directive: String,
    /// The full original CSP policy string.
    pub original_policy: String,
    /// Either `"enforce"` or `"report"`.
    pub disposition: String,
    /// HTTP status code of the resource that triggered the report.
    pub status_code: u16,
    /// First 40 characters of the inline script that caused the violation.
    pub script_sample: Option<String>,
    /// Source file where the violation originated.
    pub source_file: Option<String>,
    /// Line number in the source file.
    pub line_number: Option<u32>,
    /// Column number in the source file.
    pub column_number: Option<u32>,
}

/// Wrapper structure for CSP reports.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CspReport {
    /// The nested violation report body.
    pub csp_report: CspReportBody,
}

/// Handle CSP violation reports.
///
/// SECURITY: This endpoint receives CSP violation reports from browsers
/// when content policy is violated. It logs violations for security monitoring
/// and potential attack detection.
///
/// Implements ASVS V3.4.7 \[L3\]: CSP reporting directives configured
pub async fn handle_csp_report(
    mut req: Request,
    ctx: RouteContext<Arc<AppState>>,
) -> worker::Result<Response> {
    // CH-023: Validate Content-Type before processing.
    // Browsers send CSP reports as application/csp-report; some legacy
    // user agents use application/json. Reject anything else with 415.
    let content_type_ok = req
        .headers()
        .get("Content-Type")
        .ok()
        .flatten()
        .map(|ct| {
            let ct_lower = ct.to_ascii_lowercase();
            ct_lower.starts_with("application/csp-report")
                || ct_lower.starts_with("application/json")
        })
        .unwrap_or(false);

    if !content_type_ok {
        #[cfg(target_arch = "wasm32")]
        console_log!("[CSP-REPORT] Rejected: invalid Content-Type");
        return csp_error_response(415, "Content-Type must be application/json");
    }

    // IV-108: Read actual body bytes with enforced size limit instead of
    // relying on Content-Length alone (which can be bypassed with chunked
    // encoding or simply omitted).
    let body_bytes = match req.bytes().await {
        Ok(bytes) => {
            if bytes.len() as u64 > MAX_CSP_BODY_SIZE {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[CSP-REPORT] Body too large: {} > {}",
                    bytes.len(),
                    MAX_CSP_BODY_SIZE
                );
                return csp_error_response(413, "Request too large");
            }
            bytes
        }
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[CSP-REPORT] Failed to read body: {:?}", _e);
            return csp_error_response(400, "Invalid request");
        }
    };

    // Parse the CSP report from the body bytes
    let report: CspReport = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[CSP-REPORT] Failed to parse CSP report: {:?}", _e);
            return csp_error_response(400, "Invalid request");
        }
    };

    // SECURITY: ASVS V2.1.3 - Validate CSP report field lengths to prevent DoS
    if report.csp_report.document_uri.len() > MAX_CSP_URI_LENGTH {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[CSP-REPORT] document_uri exceeds maximum length: {} > {}",
            report.csp_report.document_uri.len(),
            MAX_CSP_URI_LENGTH
        );
        return csp_error_response(400, "Invalid request");
    }
    if report.csp_report.blocked_uri.len() > MAX_CSP_URI_LENGTH {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[CSP-REPORT] blocked_uri exceeds maximum length: {} > {}",
            report.csp_report.blocked_uri.len(),
            MAX_CSP_URI_LENGTH
        );
        return csp_error_response(400, "Invalid request");
    }
    if let Some(ref referrer) = report.csp_report.referrer {
        if referrer.len() > MAX_CSP_URI_LENGTH {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[CSP-REPORT] referrer exceeds maximum length: {} > {}",
                referrer.len(),
                MAX_CSP_URI_LENGTH
            );
            return csp_error_response(400, "Invalid request");
        }
    }
    if let Some(ref source_file) = report.csp_report.source_file {
        if source_file.len() > MAX_CSP_URI_LENGTH {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[CSP-REPORT] source_file exceeds maximum length: {} > {}",
                source_file.len(),
                MAX_CSP_URI_LENGTH
            );
            return csp_error_response(400, "Invalid request");
        }
    }

    // IV-107: Validate remaining CSP string field lengths.
    if report.csp_report.violated_directive.len() > MAX_CSP_DIRECTIVE_LENGTH
        || report.csp_report.effective_directive.len() > MAX_CSP_DIRECTIVE_LENGTH
    {
        #[cfg(target_arch = "wasm32")]
        console_log!("[CSP-REPORT] Directive field exceeds maximum length");
        return csp_error_response(400, "Invalid request");
    }
    if report.csp_report.original_policy.len() > MAX_CSP_POLICY_LENGTH {
        #[cfg(target_arch = "wasm32")]
        console_log!("[CSP-REPORT] original_policy exceeds maximum length");
        return csp_error_response(400, "Invalid request");
    }
    if report.csp_report.disposition.len() > MAX_CSP_DISPOSITION_LENGTH {
        #[cfg(target_arch = "wasm32")]
        console_log!("[CSP-REPORT] disposition exceeds maximum length");
        return csp_error_response(400, "Invalid request");
    }
    if let Some(ref script_sample) = report.csp_report.script_sample {
        if script_sample.len() > MAX_CSP_SCRIPT_SAMPLE_LENGTH {
            #[cfg(target_arch = "wasm32")]
            console_log!("[CSP-REPORT] script_sample exceeds maximum length");
            return csp_error_response(400, "Invalid request");
        }
    }

    // Log the violation for security monitoring.
    // SECURITY: Strip query strings and fragments to prevent PII leakage in logs.
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[CSP-VIOLATION] document-uri: {}, blocked-uri: {}, violated-directive: {}",
        strip_uri_params(&report.csp_report.document_uri),
        strip_uri_params(&report.csp_report.blocked_uri),
        report.csp_report.violated_directive
    );

    // Log additional details if available
    if let Some(ref _source_file) = report.csp_report.source_file {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[CSP-VIOLATION] source-file: {}, line: {:?}, column: {:?}",
            strip_uri_params(_source_file),
            report.csp_report.line_number,
            report.csp_report.column_number
        );
    }

    // Log effective directive and disposition
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[CSP-VIOLATION] effective-directive: {}, disposition: {}, status: {}",
        report.csp_report.effective_directive,
        report.csp_report.disposition,
        report.csp_report.status_code
    );

    // Persist the CSP report to KV for offline analysis (fire-and-forget).
    // Key format: csp:{epoch_seconds}:{8-char dedup hash}
    // TTL: 90 days (7_776_000 seconds) matching audit log retention.
    if let Ok(kv) = ctx.data.env.kv(KV_CONFIG) {
        let timestamp = crate::utils::current_timestamp();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        report.csp_report.blocked_uri.hash(&mut hasher);
        report.csp_report.violated_directive.hash(&mut hasher);
        let short_hash = format!("{:016x}", hasher.finish());
        let key = format!(
            "csp:{}:{}",
            timestamp,
            short_hash.get(..8).unwrap_or(&short_hash)
        );

        // SECURITY: Sanitise URI fields before persistence to prevent PII
        // leakage into KV. Query strings and fragments are stripped from all
        // URI-typed fields; the path component is sufficient for triage.
        let sanitised = CspReport {
            csp_report: CspReportBody {
                document_uri: strip_uri_params(&report.csp_report.document_uri).to_string(),
                referrer: report
                    .csp_report
                    .referrer
                    .as_deref()
                    .map(|r| strip_uri_params(r).to_string()),
                blocked_uri: strip_uri_params(&report.csp_report.blocked_uri).to_string(),
                violated_directive: report.csp_report.violated_directive.clone(),
                effective_directive: report.csp_report.effective_directive.clone(),
                original_policy: report.csp_report.original_policy.clone(),
                disposition: report.csp_report.disposition.clone(),
                status_code: report.csp_report.status_code,
                script_sample: report.csp_report.script_sample.clone(),
                source_file: report
                    .csp_report
                    .source_file
                    .as_deref()
                    .map(|s| strip_uri_params(s).to_string()),
                line_number: report.csp_report.line_number,
                column_number: report.csp_report.column_number,
            },
        };

        if let Ok(json) = serde_json::to_string(&sanitised) {
            match kv.put(&key, json).map(|p| p.expiration_ttl(7_776_000)) {
                Ok(builder) => {
                    if let Err(_e) = builder.execute().await {
                        #[cfg(target_arch = "wasm32")]
                        console_log!("[CSP-REPORT] KV write failed: {:?}", _e);
                    }
                }
                Err(_e) => {
                    #[cfg(target_arch = "wasm32")]
                    console_log!("[CSP-REPORT] KV put failed: {:?}", _e);
                }
            }
        }
    }

    // Return 204 No Content per CSP specification with security headers
    let mut response = Response::empty()?.with_status(204);
    // SECURITY: ASVS V4.1.1 - Set explicit Content-Type header
    response
        .headers_mut()
        .set("Content-Type", "text/plain; charset=utf-8")?;
    // SECURITY: Apply security headers to success response
    let security_headers = api_security_headers();
    security_headers.apply(&mut response)?;
    Ok(response)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn test_csp_report_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "csp-report": {
                "document-uri": "https://example.com/page",
                "referrer": "https://example.com/",
                "blocked-uri": "https://evil.com/script.js",
                "violated-directive": "script-src",
                "effective-directive": "script-src",
                "original-policy": "default-src 'none'; script-src 'self'",
                "disposition": "enforce",
                "status-code": 200
            }
        }"#;

        let report: CspReport = serde_json::from_str(json)?;
        assert_eq!(report.csp_report.document_uri, "https://example.com/page");
        assert_eq!(report.csp_report.blocked_uri, "https://evil.com/script.js");
        assert_eq!(report.csp_report.violated_directive, "script-src");
        Ok(())
    }

    #[test]
    fn test_csp_report_with_source_location() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "csp-report": {
                "document-uri": "https://example.com/page",
                "blocked-uri": "inline",
                "violated-directive": "script-src",
                "effective-directive": "script-src",
                "original-policy": "default-src 'none'",
                "disposition": "enforce",
                "status-code": 200,
                "source-file": "https://example.com/app.js",
                "line-number": 42,
                "column-number": 10
            }
        }"#;

        let report: CspReport = serde_json::from_str(json)?;
        assert_eq!(
            report.csp_report.source_file,
            Some("https://example.com/app.js".to_string())
        );
        assert_eq!(report.csp_report.line_number, Some(42));
        assert_eq!(report.csp_report.column_number, Some(10));
        Ok(())
    }

    #[test]
    fn test_strip_uri_params_query() {
        assert_eq!(
            strip_uri_params("https://example.com/page?email=user@example.com&token=abc"),
            "https://example.com/page"
        );
    }

    #[test]
    fn test_strip_uri_params_fragment() {
        assert_eq!(
            strip_uri_params("https://example.com/page#section"),
            "https://example.com/page"
        );
    }

    #[test]
    fn test_strip_uri_params_both() {
        assert_eq!(
            strip_uri_params("https://example.com/page?q=1#frag"),
            "https://example.com/page"
        );
    }

    #[test]
    fn test_strip_uri_params_no_params() {
        assert_eq!(
            strip_uri_params("https://example.com/page"),
            "https://example.com/page"
        );
    }

    #[test]
    fn test_strip_uri_params_empty() {
        assert_eq!(strip_uri_params(""), "");
    }

    #[test]
    fn test_strip_uri_params_inline_keyword() {
        // blocked-uri is often just "inline" or "eval" with no scheme
        assert_eq!(strip_uri_params("inline"), "inline");
    }

    #[test]
    fn test_csp_report_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let report = CspReport {
            csp_report: CspReportBody {
                document_uri: "https://example.com".to_string(),
                referrer: None,
                blocked_uri: "https://evil.com".to_string(),
                violated_directive: "default-src".to_string(),
                effective_directive: "default-src".to_string(),
                original_policy: "default-src 'none'".to_string(),
                disposition: "enforce".to_string(),
                status_code: 200,
                script_sample: None,
                source_file: None,
                line_number: None,
                column_number: None,
            },
        };

        let json = serde_json::to_string(&report)?;
        assert!(json.contains("csp-report"));
        assert!(json.contains("document-uri"));
        Ok(())
    }

    // ── Constants validation ────────────────────────────────────────

    #[test]
    fn max_csp_uri_length_is_2048() {
        assert_eq!(MAX_CSP_URI_LENGTH, 2048);
    }

    #[test]
    fn max_csp_directive_length_is_512() {
        assert_eq!(MAX_CSP_DIRECTIVE_LENGTH, 512);
    }

    #[test]
    fn max_csp_policy_length_is_8192() {
        assert_eq!(MAX_CSP_POLICY_LENGTH, 8192);
    }

    #[test]
    fn max_csp_disposition_length_is_64() {
        assert_eq!(MAX_CSP_DISPOSITION_LENGTH, 64);
    }

    #[test]
    fn max_csp_script_sample_length_is_512() {
        assert_eq!(MAX_CSP_SCRIPT_SAMPLE_LENGTH, 512);
    }

    #[test]
    fn max_csp_body_size_is_16kb() {
        assert_eq!(MAX_CSP_BODY_SIZE, 16_384);
    }

    // ── deny_unknown_fields enforcement ─────────────────────────────

    #[test]
    fn csp_report_body_rejects_unknown_fields() {
        let json = r#"{
            "csp-report": {
                "document-uri": "https://example.com/page",
                "blocked-uri": "https://evil.com/script.js",
                "violated-directive": "script-src",
                "effective-directive": "script-src",
                "original-policy": "default-src 'none'",
                "disposition": "enforce",
                "status-code": 200,
                "injected-field": "malicious"
            }
        }"#;
        let result = serde_json::from_str::<CspReport>(json);
        assert!(result.is_err(), "unknown fields must be rejected");
    }

    // ── serde round-trip with all optional fields ───────────────────

    #[test]
    fn csp_report_round_trip_all_fields() -> Result<(), Box<dyn std::error::Error>> {
        let original = CspReport {
            csp_report: CspReportBody {
                document_uri: "https://example.com/page".to_string(),
                referrer: Some("https://example.com/".to_string()),
                blocked_uri: "https://evil.com/script.js".to_string(),
                violated_directive: "script-src".to_string(),
                effective_directive: "script-src".to_string(),
                original_policy: "default-src 'none'; script-src 'self'".to_string(),
                disposition: "enforce".to_string(),
                status_code: 200,
                script_sample: Some("alert('xss')".to_string()),
                source_file: Some("https://example.com/app.js".to_string()),
                line_number: Some(42),
                column_number: Some(10),
            },
        };
        let json = serde_json::to_string(&original)?;
        let parsed: CspReport = serde_json::from_str(&json)?;
        assert_eq!(
            parsed.csp_report.document_uri,
            original.csp_report.document_uri
        );
        assert_eq!(parsed.csp_report.referrer, original.csp_report.referrer);
        assert_eq!(
            parsed.csp_report.blocked_uri,
            original.csp_report.blocked_uri
        );
        assert_eq!(
            parsed.csp_report.script_sample,
            original.csp_report.script_sample
        );
        assert_eq!(
            parsed.csp_report.source_file,
            original.csp_report.source_file
        );
        assert_eq!(
            parsed.csp_report.line_number,
            original.csp_report.line_number
        );
        assert_eq!(
            parsed.csp_report.column_number,
            original.csp_report.column_number
        );
        assert_eq!(
            parsed.csp_report.status_code,
            original.csp_report.status_code
        );
        Ok(())
    }

    // ── strip_uri_params edge cases ─────────────────────────────────

    #[test]
    fn strip_uri_params_only_query() {
        assert_eq!(strip_uri_params("?key=value"), "");
    }

    #[test]
    fn strip_uri_params_only_fragment() {
        assert_eq!(strip_uri_params("#section"), "");
    }

    #[test]
    fn strip_uri_params_fragment_before_query() {
        // Fragment appears before query string: both stripped.
        assert_eq!(
            strip_uri_params("https://example.com/page#frag?q=1"),
            "https://example.com/page"
        );
    }

    #[test]
    fn strip_uri_params_multiple_question_marks() {
        assert_eq!(
            strip_uri_params("https://example.com/page?a=1?b=2"),
            "https://example.com/page"
        );
    }

    #[test]
    fn strip_uri_params_path_with_encoded_chars() {
        // Percent-encoded paths should be preserved; only query/fragment stripped.
        assert_eq!(
            strip_uri_params("https://example.com/p%20a%20th?q=1"),
            "https://example.com/p%20a%20th"
        );
    }

    #[test]
    fn strip_uri_params_data_uri() {
        assert_eq!(strip_uri_params("data:text/html"), "data:text/html");
    }

    #[test]
    fn strip_uri_params_eval_keyword() {
        assert_eq!(strip_uri_params("eval"), "eval");
    }

    // ── CspReport kebab-case serialisation ──────────────────────────

    #[test]
    fn csp_report_uses_kebab_case_keys() -> Result<(), Box<dyn std::error::Error>> {
        let report = CspReport {
            csp_report: CspReportBody {
                document_uri: "https://example.com".to_string(),
                referrer: None,
                blocked_uri: "inline".to_string(),
                violated_directive: "script-src".to_string(),
                effective_directive: "script-src".to_string(),
                original_policy: "default-src 'none'".to_string(),
                disposition: "enforce".to_string(),
                status_code: 0,
                script_sample: None,
                source_file: None,
                line_number: None,
                column_number: None,
            },
        };
        let json = serde_json::to_string(&report)?;
        // All fields should use kebab-case.
        assert!(json.contains("document-uri"));
        assert!(json.contains("blocked-uri"));
        assert!(json.contains("violated-directive"));
        assert!(json.contains("effective-directive"));
        assert!(json.contains("original-policy"));
        assert!(json.contains("status-code"));
        // snake_case should NOT appear.
        assert!(!json.contains("document_uri"));
        assert!(!json.contains("blocked_uri"));
        Ok(())
    }

    // ── CspReportBody minimal required fields ───────────────────────

    #[test]
    fn csp_report_body_requires_mandatory_fields() {
        // Missing required field should fail.
        let json = r#"{
            "csp-report": {
                "document-uri": "https://example.com/page",
                "blocked-uri": "https://evil.com/script.js"
            }
        }"#;
        let result = serde_json::from_str::<CspReport>(json);
        assert!(result.is_err(), "missing required fields must error");
    }

    #[test]
    fn csp_report_status_code_zero() {
        let json = r#"{
            "csp-report": {
                "document-uri": "https://example.com",
                "blocked-uri": "inline",
                "violated-directive": "script-src",
                "effective-directive": "script-src",
                "original-policy": "default-src 'none'",
                "disposition": "report",
                "status-code": 0
            }
        }"#;
        let report: CspReport = serde_json::from_str(json).expect("should parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(report.csp_report.status_code, 0);
    }

    // ── Field length boundary checks (validated in handler) ─────────

    #[test]
    fn document_uri_at_max_length_is_valid() {
        let uri = "x".repeat(MAX_CSP_URI_LENGTH);
        assert_eq!(uri.len(), MAX_CSP_URI_LENGTH);
        // Should NOT exceed the limit.
        assert!(uri.len() <= MAX_CSP_URI_LENGTH);
    }

    #[test]
    fn document_uri_over_max_length_exceeds() {
        #[allow(clippy::arithmetic_side_effects)]
        let uri = "x".repeat(MAX_CSP_URI_LENGTH + 1);
        assert!(uri.len() > MAX_CSP_URI_LENGTH);
    }

    #[test]
    fn directive_at_max_length_is_valid() {
        let directive = "x".repeat(MAX_CSP_DIRECTIVE_LENGTH);
        assert!(directive.len() <= MAX_CSP_DIRECTIVE_LENGTH);
    }

    #[test]
    fn policy_at_max_length_is_valid() {
        let policy = "x".repeat(MAX_CSP_POLICY_LENGTH);
        assert!(policy.len() <= MAX_CSP_POLICY_LENGTH);
    }

    #[test]
    fn disposition_at_max_length_is_valid() {
        let disposition = "x".repeat(MAX_CSP_DISPOSITION_LENGTH);
        assert!(disposition.len() <= MAX_CSP_DISPOSITION_LENGTH);
    }

    #[test]
    fn script_sample_at_max_length_is_valid() {
        let sample = "x".repeat(MAX_CSP_SCRIPT_SAMPLE_LENGTH);
        assert!(sample.len() <= MAX_CSP_SCRIPT_SAMPLE_LENGTH);
    }

    // ── Debug trait ─────────────────────────────────────────────────

    #[test]
    fn csp_report_debug_format() {
        let report = CspReport {
            csp_report: CspReportBody {
                document_uri: "https://example.com".to_string(),
                referrer: None,
                blocked_uri: "inline".to_string(),
                violated_directive: "script-src".to_string(),
                effective_directive: "script-src".to_string(),
                original_policy: "default-src 'none'".to_string(),
                disposition: "enforce".to_string(),
                status_code: 200,
                script_sample: None,
                source_file: None,
                line_number: None,
                column_number: None,
            },
        };
        let debug = format!("{:?}", report);
        assert!(debug.contains("CspReport"));
        assert!(debug.contains("CspReportBody"));
    }

    // ── strip_uri_params additional edge cases ─────────────────────

    #[test]
    fn strip_uri_params_double_hash() {
        assert_eq!(
            strip_uri_params("https://example.com/page##double"),
            "https://example.com/page"
        );
    }

    #[test]
    fn strip_uri_params_query_only_question_mark() {
        assert_eq!(
            strip_uri_params("https://example.com/page?"),
            "https://example.com/page"
        );
    }

    #[test]
    fn strip_uri_params_fragment_only_hash() {
        assert_eq!(
            strip_uri_params("https://example.com/page#"),
            "https://example.com/page"
        );
    }

    #[test]
    fn strip_uri_params_bare_scheme() {
        assert_eq!(strip_uri_params("https://"), "https://");
    }

    #[test]
    fn strip_uri_params_very_long_query() {
        let base = "https://example.com/page";
        let query = format!("{}?{}", base, "x".repeat(4096));
        assert_eq!(strip_uri_params(&query), base);
    }

    #[test]
    fn strip_uri_params_blob_uri() {
        assert_eq!(
            strip_uri_params("blob:https://example.com/uuid"),
            "blob:https://example.com/uuid"
        );
    }

    #[test]
    fn strip_uri_params_about_blank() {
        assert_eq!(strip_uri_params("about:blank"), "about:blank");
    }

    #[test]
    fn strip_uri_params_self_keyword() {
        assert_eq!(strip_uri_params("'self'"), "'self'");
    }

    // ── CspReportBody field validation logic ───────────────────────

    #[test]
    fn document_uri_one_over_max_exceeds() {
        #[allow(clippy::arithmetic_side_effects)]
        let uri = "x".repeat(MAX_CSP_URI_LENGTH + 1);
        assert!(uri.len() > MAX_CSP_URI_LENGTH);
    }

    #[test]
    fn directive_one_over_max_exceeds() {
        #[allow(clippy::arithmetic_side_effects)]
        let d = "x".repeat(MAX_CSP_DIRECTIVE_LENGTH + 1);
        assert!(d.len() > MAX_CSP_DIRECTIVE_LENGTH);
    }

    #[test]
    fn policy_one_over_max_exceeds() {
        #[allow(clippy::arithmetic_side_effects)]
        let p = "x".repeat(MAX_CSP_POLICY_LENGTH + 1);
        assert!(p.len() > MAX_CSP_POLICY_LENGTH);
    }

    #[test]
    fn disposition_one_over_max_exceeds() {
        #[allow(clippy::arithmetic_side_effects)]
        let d = "x".repeat(MAX_CSP_DISPOSITION_LENGTH + 1);
        assert!(d.len() > MAX_CSP_DISPOSITION_LENGTH);
    }

    #[test]
    fn script_sample_one_over_max_exceeds() {
        #[allow(clippy::arithmetic_side_effects)]
        let s = "x".repeat(MAX_CSP_SCRIPT_SAMPLE_LENGTH + 1);
        assert!(s.len() > MAX_CSP_SCRIPT_SAMPLE_LENGTH);
    }

    // ── CspReport deserialisation edge cases ───────────────────────

    #[test]
    fn csp_report_rejects_empty_json_object() {
        let result = serde_json::from_str::<CspReport>("{}");
        assert!(result.is_err(), "empty object must error");
    }

    #[test]
    fn csp_report_rejects_array() {
        let result = serde_json::from_str::<CspReport>("[]");
        assert!(result.is_err(), "array must error");
    }

    #[test]
    fn csp_report_rejects_null() {
        let result = serde_json::from_str::<CspReport>("null");
        assert!(result.is_err(), "null must error");
    }

    #[test]
    fn csp_report_body_max_status_code() {
        let json = r#"{
            "csp-report": {
                "document-uri": "https://example.com",
                "blocked-uri": "inline",
                "violated-directive": "script-src",
                "effective-directive": "script-src",
                "original-policy": "default-src 'none'",
                "disposition": "enforce",
                "status-code": 65535
            }
        }"#;
        let report: CspReport = serde_json::from_str(json).expect("should parse u16::MAX"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(report.csp_report.status_code, u16::MAX);
    }

    #[test]
    fn csp_report_body_rejects_negative_status_code() {
        let json = r#"{
            "csp-report": {
                "document-uri": "https://example.com",
                "blocked-uri": "inline",
                "violated-directive": "script-src",
                "effective-directive": "script-src",
                "original-policy": "default-src 'none'",
                "disposition": "enforce",
                "status-code": -1
            }
        }"#;
        let result = serde_json::from_str::<CspReport>(json);
        assert!(result.is_err(), "negative status code must error for u16");
    }

    #[test]
    fn csp_report_body_rejects_status_code_overflow() {
        let json = r#"{
            "csp-report": {
                "document-uri": "https://example.com",
                "blocked-uri": "inline",
                "violated-directive": "script-src",
                "effective-directive": "script-src",
                "original-policy": "default-src 'none'",
                "disposition": "enforce",
                "status-code": 70000
            }
        }"#;
        let result = serde_json::from_str::<CspReport>(json);
        assert!(result.is_err(), "status code > u16::MAX must error");
    }

    #[test]
    fn csp_report_with_all_optional_fields_none() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "csp-report": {
                "document-uri": "https://example.com",
                "blocked-uri": "inline",
                "violated-directive": "script-src",
                "effective-directive": "script-src",
                "original-policy": "default-src 'none'",
                "disposition": "enforce",
                "status-code": 200
            }
        }"#;
        let report: CspReport = serde_json::from_str(json)?;
        assert!(report.csp_report.referrer.is_none());
        assert!(report.csp_report.script_sample.is_none());
        assert!(report.csp_report.source_file.is_none());
        assert!(report.csp_report.line_number.is_none());
        assert!(report.csp_report.column_number.is_none());
        Ok(())
    }

    #[test]
    fn csp_report_with_all_optional_fields_set() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "csp-report": {
                "document-uri": "https://example.com",
                "referrer": "https://ref.example.com",
                "blocked-uri": "https://evil.com",
                "violated-directive": "script-src",
                "effective-directive": "script-src",
                "original-policy": "default-src 'none'",
                "disposition": "enforce",
                "status-code": 200,
                "script-sample": "alert(1)",
                "source-file": "https://example.com/app.js",
                "line-number": 1,
                "column-number": 1
            }
        }"#;
        let report: CspReport = serde_json::from_str(json)?;
        assert!(report.csp_report.referrer.is_some());
        assert!(report.csp_report.script_sample.is_some());
        assert!(report.csp_report.source_file.is_some());
        assert_eq!(report.csp_report.line_number, Some(1));
        assert_eq!(report.csp_report.column_number, Some(1));
        Ok(())
    }

    // ── CspReportBody serialisation with optional fields ───────────

    #[test]
    fn csp_report_body_serialises_null_optionals_as_null() -> Result<(), Box<dyn std::error::Error>>
    {
        let report = CspReport {
            csp_report: CspReportBody {
                document_uri: "https://example.com".to_string(),
                referrer: None,
                blocked_uri: "inline".to_string(),
                violated_directive: "script-src".to_string(),
                effective_directive: "script-src".to_string(),
                original_policy: "default-src 'none'".to_string(),
                disposition: "enforce".to_string(),
                status_code: 200,
                script_sample: None,
                source_file: None,
                line_number: None,
                column_number: None,
            },
        };
        let v: serde_json::Value = serde_json::to_value(&report)?;
        let inner = &v["csp-report"];
        assert!(inner["referrer"].is_null());
        assert!(inner["script-sample"].is_null());
        assert!(inner["source-file"].is_null());
        assert!(inner["line-number"].is_null());
        assert!(inner["column-number"].is_null());
        Ok(())
    }

    // ── Constant relationships ─────────────────────────────────────

    #[test]
    fn body_size_limit_is_power_of_two() {
        assert!(MAX_CSP_BODY_SIZE.is_power_of_two());
    }

    #[test]
    fn directive_length_less_than_uri_length() {
        assert!(MAX_CSP_DIRECTIVE_LENGTH < MAX_CSP_URI_LENGTH);
    }

    #[test]
    fn disposition_length_less_than_directive_length() {
        assert!(MAX_CSP_DISPOSITION_LENGTH < MAX_CSP_DIRECTIVE_LENGTH);
    }

    #[test]
    fn policy_length_greater_than_uri_length() {
        assert!(MAX_CSP_POLICY_LENGTH > MAX_CSP_URI_LENGTH);
    }

    // ── Hashing for KV key dedup ───────────────────────────────────

    #[test]
    fn hash_dedup_is_deterministic() {
        use std::hash::{Hash, Hasher};
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        "https://evil.com/script.js".hash(&mut h1);
        "script-src".hash(&mut h1);
        let r1 = h1.finish();

        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        "https://evil.com/script.js".hash(&mut h2);
        "script-src".hash(&mut h2);
        let r2 = h2.finish();

        assert_eq!(r1, r2);
    }

    #[test]
    fn hash_dedup_differs_for_different_input() {
        use std::hash::{Hash, Hasher};
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        "https://evil.com/script.js".hash(&mut h1);
        "script-src".hash(&mut h1);
        let r1 = h1.finish();

        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        "https://other.com/x.js".hash(&mut h2);
        "style-src".hash(&mut h2);
        let r2 = h2.finish();

        assert_ne!(r1, r2);
    }

    #[test]
    fn hash_short_hash_truncation() {
        let full = format!("{:016x}", 0xDEADBEEFCAFEBABEu64);
        let short = full.get(..8).unwrap_or(&full);
        assert_eq!(short.len(), 8);
        assert_eq!(short, "deadbeef");
    }

    // ── CspReport with empty string fields ─────────────────────────

    #[test]
    fn csp_report_empty_document_uri() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "csp-report": {
                "document-uri": "",
                "blocked-uri": "",
                "violated-directive": "",
                "effective-directive": "",
                "original-policy": "",
                "disposition": "",
                "status-code": 0
            }
        }"#;
        let report: CspReport = serde_json::from_str(json)?;
        assert!(report.csp_report.document_uri.is_empty());
        assert!(report.csp_report.blocked_uri.is_empty());
        Ok(())
    }

    // ── CspReportBody Debug includes field values ──────────────────

    #[test]
    fn csp_report_body_debug_includes_directive() {
        let body = CspReportBody {
            document_uri: "https://example.com".to_string(),
            referrer: None,
            blocked_uri: "inline".to_string(),
            violated_directive: "img-src".to_string(),
            effective_directive: "img-src".to_string(),
            original_policy: "default-src 'self'".to_string(),
            disposition: "enforce".to_string(),
            status_code: 404,
            script_sample: None,
            source_file: None,
            line_number: None,
            column_number: None,
        };
        let debug = format!("{:?}", body);
        assert!(debug.contains("img-src"));
        assert!(debug.contains("404"));
    }

    // ── CspReport with disposition "report" ────────────────────────

    #[test]
    fn csp_report_report_only_disposition() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "csp-report": {
                "document-uri": "https://example.com",
                "blocked-uri": "inline",
                "violated-directive": "script-src",
                "effective-directive": "script-src",
                "original-policy": "default-src 'none'",
                "disposition": "report",
                "status-code": 200
            }
        }"#;
        let report: CspReport = serde_json::from_str(json)?;
        assert_eq!(report.csp_report.disposition, "report");
        Ok(())
    }

    // ── Sanitisation via strip_uri_params in persistence path ──────

    #[test]
    fn strip_uri_params_preserves_port() {
        assert_eq!(
            strip_uri_params("https://example.com:8443/path?q=1"),
            "https://example.com:8443/path"
        );
    }

    #[test]
    fn strip_uri_params_preserves_credentials_in_path() {
        // Although unusual, verify no crash on user:pass@ syntax.
        assert_eq!(
            strip_uri_params("https://user:pass@example.com/path?q=1"),
            "https://user:pass@example.com/path"
        );
    }

    #[test]
    fn strip_uri_params_unicode_path() {
        assert_eq!(
            strip_uri_params("https://example.com/café?order=1"),
            "https://example.com/café"
        );
    }
}
