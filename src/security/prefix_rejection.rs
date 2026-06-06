// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Sandbox-prefix rejection for the provii-verifier edge.
//!
//! Mirrors the TypeScript middleware in `provii-management/src/middleware/
//! prefix-rejection.ts`. Refuses any request that carries a sandbox-only
//! identifier prefix on a production deployment.
//!
//! The docs-sandbox gateway (provii-issuer) mints `docs-sbx-*`
//! client credentials; the mobile-sandbox flow mints `mwallet-sbx-*`
//! credentials. Both exist only in sandbox KV; routing either at a
//! production Worker indicates a caller misconfiguration or an active
//! probe. We fail fast at the edge rather than let the request reach
//! authentication, idempotency, rate limiting, or any handler code.
//!
//! Scope of inspection:
//!
//!   - Path segments of the request URL.
//!   - Every value of every query-string parameter.
//!   - The caller-identifying headers `X-Client-Id`, `X-API-Key`,
//!     and `Authorization` (both `Bearer <token>` and raw token forms).
//!
//! This module DOES NOT inspect request bodies. provii-verifier bodies are
//! proof payloads and session binders; none of the on-wire fields are
//! expected to carry a bare client_id string. Scanning the body would
//! force us to buffer and re-emit it on every request, which is not
//! justified by the threat model. The provii-management middleware scans
//! bodies because it accepts admin-authored JSON with arbitrary client
//! identifier fields; provii-verifier does not.
//!
//! SECURITY: All comparisons here operate on non-secret identifier
//! prefixes. Constant-time comparison is neither required nor used.
//! Rejection short-circuits on the first hit to avoid needless work on
//! attacker-controlled input.
//!
//! Pairs with:
//!
//!   - `build.rs` (compile-time guard, compile-time guard)
//!   - `.github/workflows/prod-bundle-check.yml` (CI-time grep, post-link grep)
//!
//! giving three independent defences against sandbox bleedthrough.

#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use worker::{Env, Headers, Request, Response, Result as WorkerResult};

/// Prefixes that identify sandbox-only credentials.
///
/// Keep this list in sync with the sibling TypeScript middleware and the
/// CI grep workflow; all three must agree on which prefixes are gated.
const SANDBOX_PREFIXES: &[&str] = &["docs-sbx-", "mwallet-sbx-"];

/// Canonical rejection body. Shape matches the provii-management response
/// so that operators troubleshooting an unexpected 401 can correlate
/// across services.
const REJECTION_BODY: &str = r#"{"error":"Access denied","code":"prefix_not_permitted"}"#;

/// Return `true` if `value` begins with any configured sandbox prefix.
///
/// For `Authorization`-style values this helper strips a leading scheme
/// token (`Bearer `, `Basic `, etc.) before comparing, so a credential
/// carried as `Authorization: Bearer docs-sbx-...` is still caught.
fn matches_sandbox_prefix(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    // Check the raw value first. If the caller passed a bare token without
    // an auth-scheme prefix this catches it directly.
    if begins_with_any_prefix(value) {
        return true;
    }
    // Authorization headers may arrive as `Bearer <token>`, `Basic ...`,
    // or a handful of other short schemes. If the first whitespace-delimited
    // segment is <= 15 ASCII characters, treat it as a scheme and inspect
    // the remainder. Longer leading segments are assumed to be credential
    // material rather than a scheme and are not stripped.
    if let Some((scheme, rest)) = value.split_once(' ') {
        if scheme.len() <= 15 && !scheme.is_empty() {
            let after = rest.trim_start();
            if begins_with_any_prefix(after) {
                return true;
            }
        }
    }
    false
}

/// Plain `str::starts_with` loop over the configured sandbox prefixes.
fn begins_with_any_prefix(candidate: &str) -> bool {
    for prefix in SANDBOX_PREFIXES {
        if candidate.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// Outcome of a prefix scan.
#[derive(Debug, PartialEq, Eq)]
pub enum PrefixCheck {
    /// No sandbox-prefixed value observed. Request should continue.
    Allow,
    /// Sandbox-prefixed value observed. The `source` field describes
    /// where it was found; it is used only for structured diagnostics
    /// and never echoed in the 401 body.
    Reject { source: &'static str },
}

/// Inspect a request's URL and headers for sandbox-prefixed values.
///
/// Pure function, no side effects. Kept separate from the Worker-level
/// entry point so unit tests can exercise it without a Worker runtime.
///
/// Returns `PrefixCheck::Allow` when no sandbox prefix is observed.
pub fn check_request_inputs(
    path: &str,
    query: &str,
    header_iter: impl IntoIterator<Item = (String, String)>,
) -> PrefixCheck {
    // Path-segment scan. Empty segments (leading/trailing slash, double
    // slashes) are skipped because they cannot carry a prefix. Each
    // segment is URL-decoded so that a prefix encoded as
    // `docs-sbx-%66oo` is still caught. Malformed percent-encoding
    // falls back to the raw segment.
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        let decoded = percent_decode(segment);
        if matches_sandbox_prefix(decoded.as_str()) {
            return PrefixCheck::Reject { source: "path" };
        }
    }

    // Query-string scan. Iterate all `k=v` pairs and check both sides.
    // A missing `=` yields a value-only key (e.g. `?docs-sbx-...`);
    // the key still counts as a sandbox-prefixed value in that case.
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let decoded_key = percent_decode(key);
        if matches_sandbox_prefix(&decoded_key) {
            return PrefixCheck::Reject { source: "query" };
        }
        if !value.is_empty() {
            let decoded_value = percent_decode(value);
            if matches_sandbox_prefix(&decoded_value) {
                return PrefixCheck::Reject { source: "query" };
            }
        }
    }

    // Header scan. Case-insensitive header names, raw values.
    for (name, value) in header_iter {
        let lower = name.to_ascii_lowercase();
        let inspected = matches!(
            lower.as_str(),
            "x-client-id" | "x-api-key" | "authorization"
        );
        if inspected && matches_sandbox_prefix(&value) {
            return PrefixCheck::Reject { source: "header" };
        }
    }

    PrefixCheck::Allow
}

/// Best-effort percent-decode. Invalid sequences fall through as-is.
///
/// We deliberately avoid a heavy URL-parsing dependency here. The worker
/// runtime already decodes the pathname for us in most cases; this
/// helper exists to catch the rare path where `%xx` sequences are still
/// present in the raw segment. Written without index arithmetic or
/// slicing so it passes the crate's strict clippy gate.
fn percent_decode(input: &str) -> String {
    if !input.contains('%') {
        return input.to_string();
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut iter = input.bytes().peekable();
    while let Some(b) = iter.next() {
        if b == b'%' {
            // Peek without consuming so malformed sequences fall through
            // as the original bytes rather than being eaten.
            let next1 = iter.peek().copied();
            let hi = next1.and_then(hex_digit);
            if let Some(h) = hi {
                let raw_hi = next1.unwrap_or(b'%');
                iter.next();
                let next2 = iter.peek().copied();
                let lo = next2.and_then(hex_digit);
                if let Some(l) = lo {
                    iter.next();
                    // Both nibbles valid. Compose the decoded byte. `h`
                    // and `l` are in 0..=15 so `saturating_*` is redundant
                    // but cheap; it pacifies `arithmetic_side_effects`.
                    out.push(h.saturating_mul(16).saturating_add(l));
                    continue;
                }
                // First nibble valid, second not: emit literal `%` then
                // the first nibble's raw byte (preserving case).
                out.push(b'%');
                out.push(raw_hi);
                continue;
            }
            // No hex after `%`: emit the literal `%`.
            out.push(b'%');
            continue;
        }
        out.push(b);
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.saturating_sub(b'0')),
        b'a'..=b'f' => Some(b.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(b.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

/// Build a 401 `prefix_not_permitted` response.
pub fn rejection_response() -> WorkerResult<Response> {
    let body = REJECTION_BODY.as_bytes().to_vec();
    let mut response = Response::from_bytes(body)?.with_status(401);
    let headers = response.headers_mut();
    headers.set("Content-Type", "application/json; charset=utf-8")?;
    headers.set("Cache-Control", "no-store")?;
    Ok(response)
}

/// Convenience wrapper around [`check_request_inputs`] that pulls the
/// inputs straight off a Worker `Request`, logs a structured rejection
/// event, and returns a fully-formed 401 `Response` when a sandbox
/// prefix is observed.
///
/// Production environments trigger the check. Sandbox deployments
/// (`env.var("ENVIRONMENT")? == "sandbox"`) are a no-op.
///
/// # Errors
///
/// Returns `Err` only if the underlying `Response` construction fails,
/// which on the Workers runtime indicates an out-of-memory condition.
pub fn check_request(req: &Request, env: &Env) -> WorkerResult<Option<Response>> {
    let environment = env
        .var("ENVIRONMENT")
        .map(|v| v.to_string())
        .unwrap_or_default();
    if environment == "sandbox" {
        return Ok(None);
    }

    let url = match req.url() {
        Ok(u) => u,
        Err(_) => {
            // If the URL is malformed the router will reject the request
            // with its own error anyway; don't produce a misleading 401.
            return Ok(None);
        }
    };
    let path = url.path().to_string();
    let query = url.query().unwrap_or("").to_string();

    let headers = collect_header_pairs(req.headers());

    match check_request_inputs(&path, &query, headers) {
        PrefixCheck::Allow => Ok(None),
        PrefixCheck::Reject { source: _source } => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] Sandbox-prefixed {} on production surface: path={}",
                _source,
                path
            );
            rejection_response().map(Some)
        }
    }
}

/// Materialise the headers we care about into owned `(name, value)`
/// pairs. Keeping this separate from `check_request_inputs` means the
/// pure function stays Worker-agnostic and unit-testable.
fn collect_header_pairs(headers: &Headers) -> Vec<(String, String)> {
    const INSPECTED: &[&str] = &["x-client-id", "x-api-key", "authorization"];
    let mut out = Vec::with_capacity(INSPECTED.len());
    for name in INSPECTED {
        if let Ok(Some(value)) = headers.get(name) {
            out.push(((*name).to_string(), value));
        }
    }
    out
}

// Integration tests live in `tests/security/prefix_rejection_test.rs`.
// Unit tests below exercise the pure-function surface on native.

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic
)]
mod tests {
    use super::*;

    // ── begins_with_any_prefix ──────────────────────────────────────

    #[test]
    fn begins_with_docs_sbx_prefix() {
        assert!(begins_with_any_prefix("docs-sbx-abc123"));
    }

    #[test]
    fn begins_with_mwallet_sbx_prefix() {
        assert!(begins_with_any_prefix("mwallet-sbx-xyz"));
    }

    #[test]
    fn rejects_non_sandbox_prefix() {
        assert!(!begins_with_any_prefix("rp_sandbox_abc"));
        assert!(!begins_with_any_prefix("pk_live_abc"));
        assert!(!begins_with_any_prefix(""));
    }

    #[test]
    fn partial_prefix_not_matched() {
        assert!(!begins_with_any_prefix("docs-sb"));
        assert!(!begins_with_any_prefix("mwallet-sbx"));
    }

    #[test]
    fn exact_prefix_with_empty_suffix_matches() {
        // The prefix itself with nothing after should still match starts_with.
        assert!(begins_with_any_prefix("docs-sbx-"));
        assert!(begins_with_any_prefix("mwallet-sbx-"));
    }

    // ── matches_sandbox_prefix ──────────────────────────────────────

    #[test]
    fn empty_value_never_matches() {
        assert!(!matches_sandbox_prefix(""));
    }

    #[test]
    fn bare_token_matches() {
        assert!(matches_sandbox_prefix("docs-sbx-token123"));
    }

    #[test]
    fn bearer_scheme_stripped() {
        assert!(matches_sandbox_prefix("Bearer docs-sbx-token123"));
    }

    #[test]
    fn basic_scheme_stripped() {
        assert!(matches_sandbox_prefix("Basic mwallet-sbx-cred"));
    }

    #[test]
    fn scheme_longer_than_15_chars_not_stripped() {
        // A scheme longer than 15 characters is assumed to be credential material.
        let long_scheme = "a]234567890123456"; // 17 chars
        let value = format!("{} docs-sbx-token", long_scheme);
        // The raw value does not start with a sandbox prefix.
        // The scheme is > 15 chars so it won't be stripped.
        assert!(!matches_sandbox_prefix(&value));
    }

    #[test]
    fn scheme_exactly_15_chars_stripped() {
        let scheme = "a23456789012345"; // 15 chars
        let value = format!("{} docs-sbx-token", scheme);
        assert!(matches_sandbox_prefix(&value));
    }

    #[test]
    fn non_sandbox_bearer_token_not_matched() {
        assert!(!matches_sandbox_prefix("Bearer pk_live_abc123"));
    }

    #[test]
    fn multiple_spaces_after_scheme_stripped() {
        // trim_start on the remainder should handle leading spaces.
        assert!(matches_sandbox_prefix("Bearer   docs-sbx-token"));
    }

    // ── percent_decode ──────────────────────────────────────────────

    #[test]
    fn no_percent_returns_input() {
        assert_eq!(percent_decode("hello"), "hello");
    }

    #[test]
    fn simple_percent_decode() {
        // %41 = 'A'
        assert_eq!(percent_decode("%41"), "A");
    }

    #[test]
    fn multiple_encoded_chars() {
        // %48%65%6c%6c%6f = "Hello"
        assert_eq!(percent_decode("%48%65%6c%6c%6f"), "Hello");
    }

    #[test]
    fn malformed_single_nibble_passthrough() {
        // %4 followed by non-hex should emit literal %4
        assert_eq!(percent_decode("%4g"), "%4g");
    }

    #[test]
    fn trailing_percent_passthrough() {
        assert_eq!(percent_decode("abc%"), "abc%");
    }

    #[test]
    fn percent_only_passthrough() {
        assert_eq!(percent_decode("%"), "%");
    }

    #[test]
    fn percent_followed_by_non_hex_passthrough() {
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn mixed_encoded_and_plain() {
        assert_eq!(percent_decode("a%42c"), "aBc");
    }

    #[test]
    fn empty_input() {
        assert_eq!(percent_decode(""), "");
    }

    #[test]
    fn uppercase_hex_decoded() {
        // %4F = 'O'
        assert_eq!(percent_decode("%4F"), "O");
    }

    // ── hex_digit ───────────────────────────────────────────────────

    #[test]
    fn hex_digit_range() {
        assert_eq!(hex_digit(b'0'), Some(0));
        assert_eq!(hex_digit(b'9'), Some(9));
        assert_eq!(hex_digit(b'a'), Some(10));
        assert_eq!(hex_digit(b'f'), Some(15));
        assert_eq!(hex_digit(b'A'), Some(10));
        assert_eq!(hex_digit(b'F'), Some(15));
        assert_eq!(hex_digit(b'g'), None);
        assert_eq!(hex_digit(b'G'), None);
        assert_eq!(hex_digit(b' '), None);
        assert_eq!(hex_digit(b'z'), None);
    }

    // ── check_request_inputs: path scanning ─────────────────────────

    #[test]
    fn clean_path_allowed() {
        let result = check_request_inputs("/v1/challenge", "", Vec::<(String, String)>::new());
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn sandbox_prefix_in_path_segment_rejected() {
        let result = check_request_inputs(
            "/v1/docs-sbx-client/challenge",
            "",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Reject { source: "path" });
    }

    #[test]
    fn mwallet_prefix_in_path_rejected() {
        let result = check_request_inputs(
            "/api/mwallet-sbx-device123",
            "",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Reject { source: "path" });
    }

    #[test]
    fn percent_encoded_prefix_in_path_rejected() {
        // "docs-sbx-" with 'd' encoded as %64
        let result =
            check_request_inputs("/v1/%64ocs-sbx-client", "", Vec::<(String, String)>::new());
        assert_eq!(result, PrefixCheck::Reject { source: "path" });
    }

    #[test]
    fn empty_path_segments_skipped() {
        // Double slashes produce empty segments that should be skipped.
        let result = check_request_inputs("//v1//challenge//", "", Vec::<(String, String)>::new());
        assert_eq!(result, PrefixCheck::Allow);
    }

    // ── check_request_inputs: query scanning ────────────────────────

    #[test]
    fn sandbox_prefix_in_query_value_rejected() {
        let result = check_request_inputs(
            "/v1/challenge",
            "client_id=docs-sbx-abc",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Reject { source: "query" });
    }

    #[test]
    fn sandbox_prefix_in_query_key_rejected() {
        let result = check_request_inputs(
            "/v1/challenge",
            "docs-sbx-param=value",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Reject { source: "query" });
    }

    #[test]
    fn clean_query_allowed() {
        let result = check_request_inputs(
            "/v1/challenge",
            "client_id=rp_live_abc&format=json",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn empty_query_allowed() {
        let result = check_request_inputs("/v1/challenge", "", Vec::<(String, String)>::new());
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn query_valueless_key_with_prefix_rejected() {
        // Query param with no `=`: the key itself is the prefix candidate.
        let result = check_request_inputs(
            "/v1/challenge",
            "docs-sbx-key",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Reject { source: "query" });
    }

    #[test]
    fn percent_encoded_prefix_in_query_rejected() {
        // mwallet-sbx- with 'm' encoded as %6d
        let result = check_request_inputs(
            "/v1/challenge",
            "token=%6dwallet-sbx-abc",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Reject { source: "query" });
    }

    // ── check_request_inputs: header scanning ───────────────────────

    #[test]
    fn x_client_id_header_with_sandbox_prefix_rejected() {
        let headers = vec![("x-client-id".to_string(), "docs-sbx-client".to_string())];
        let result = check_request_inputs("/v1/challenge", "", headers);
        assert_eq!(result, PrefixCheck::Reject { source: "header" });
    }

    #[test]
    fn x_api_key_header_with_sandbox_prefix_rejected() {
        let headers = vec![("x-api-key".to_string(), "mwallet-sbx-key".to_string())];
        let result = check_request_inputs("/v1/challenge", "", headers);
        assert_eq!(result, PrefixCheck::Reject { source: "header" });
    }

    #[test]
    fn authorization_header_with_bearer_sandbox_rejected() {
        let headers = vec![(
            "authorization".to_string(),
            "Bearer docs-sbx-token".to_string(),
        )];
        let result = check_request_inputs("/v1/challenge", "", headers);
        assert_eq!(result, PrefixCheck::Reject { source: "header" });
    }

    #[test]
    fn non_inspected_header_ignored() {
        // Headers that are not in the inspected set should not trigger rejection.
        let headers = vec![("x-request-id".to_string(), "docs-sbx-request".to_string())];
        let result = check_request_inputs("/v1/challenge", "", headers);
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn clean_authorization_header_allowed() {
        let headers = vec![(
            "authorization".to_string(),
            "Bearer pk_live_token".to_string(),
        )];
        let result = check_request_inputs("/v1/challenge", "", headers);
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn case_insensitive_header_name_match() {
        // The check lowercases header names before comparing.
        let headers = vec![("X-Client-Id".to_string(), "docs-sbx-client".to_string())];
        let result = check_request_inputs("/v1/challenge", "", headers);
        assert_eq!(result, PrefixCheck::Reject { source: "header" });
    }

    // ── check_request_inputs: combined scanning priority ────────────

    #[test]
    fn path_rejection_short_circuits_before_query() {
        // Path has the prefix; query also has it. Path should be reported.
        let result = check_request_inputs(
            "/v1/docs-sbx-client",
            "token=mwallet-sbx-abc",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Reject { source: "path" });
    }

    #[test]
    fn query_rejection_short_circuits_before_header() {
        let headers = vec![("x-api-key".to_string(), "docs-sbx-key".to_string())];
        let result = check_request_inputs("/v1/challenge", "id=mwallet-sbx-abc", headers);
        assert_eq!(result, PrefixCheck::Reject { source: "query" });
    }

    // ── SANDBOX_PREFIXES constant ───────────────────────────────────

    #[test]
    fn sandbox_prefixes_all_end_with_dash() {
        for prefix in SANDBOX_PREFIXES {
            assert!(
                prefix.ends_with('-'),
                "prefix '{}' must end with '-'",
                prefix
            );
        }
    }

    #[test]
    fn sandbox_prefixes_count() {
        // Ensure the constant has exactly the expected number of prefixes.
        assert_eq!(SANDBOX_PREFIXES.len(), 2);
    }

    // ── REJECTION_BODY constant ─────────────────────────────────────

    #[test]
    fn rejection_body_is_valid_json() {
        let parsed: serde_json::Value = serde_json::from_str(REJECTION_BODY).expect("valid JSON"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(parsed["error"], "Access denied");
        assert_eq!(parsed["code"], "prefix_not_permitted");
    }

    // ── PrefixCheck enum ────────────────────────────────────────────

    #[test]
    fn prefix_check_debug() {
        let allow = PrefixCheck::Allow;
        let reject = PrefixCheck::Reject { source: "path" };
        assert!(format!("{:?}", allow).contains("Allow"));
        assert!(format!("{:?}", reject).contains("path"));
    }

    #[test]
    fn prefix_check_eq() {
        assert_eq!(PrefixCheck::Allow, PrefixCheck::Allow);
        assert_eq!(
            PrefixCheck::Reject { source: "query" },
            PrefixCheck::Reject { source: "query" }
        );
        assert_ne!(PrefixCheck::Allow, PrefixCheck::Reject { source: "path" });
        assert_ne!(
            PrefixCheck::Reject { source: "path" },
            PrefixCheck::Reject { source: "query" }
        );
    }

    // ── matches_sandbox_prefix: additional edge cases ──────────────────

    #[test]
    fn scheme_empty_before_space_not_stripped() {
        // " docs-sbx-token" has an empty segment before the space. Empty scheme
        // is not stripped because scheme.is_empty() guard catches it.
        // But the raw value " docs-sbx-token" does not start with prefix either.
        assert!(!matches_sandbox_prefix(" docs-sbx-token"));
    }

    #[test]
    fn no_space_in_value_only_raw_check() {
        // No space means no scheme stripping path. Only the raw prefix check runs.
        assert!(matches_sandbox_prefix("mwallet-sbx-test"));
        assert!(!matches_sandbox_prefix("normal-token-value"));
    }

    #[test]
    fn scheme_with_tab_not_stripped() {
        // split_once(' ') only splits on space, not tab.
        let value = "Bearer\tdocs-sbx-token";
        assert!(!matches_sandbox_prefix(value));
    }

    #[test]
    fn sandbox_prefix_in_middle_of_value_not_matched() {
        // starts_with means only the beginning counts.
        assert!(!matches_sandbox_prefix("some-docs-sbx-thing"));
    }

    #[test]
    fn bearer_with_mwallet_prefix() {
        assert!(matches_sandbox_prefix("Bearer mwallet-sbx-device42"));
    }

    // ── percent_decode: additional edge cases ──────────────────────────

    #[test]
    fn percent_decode_double_encoded() {
        // %2564 = first pass decodes %25 -> '%', leaving '64'.
        // So percent_decode("%2564") = "%64" (single pass only).
        assert_eq!(percent_decode("%2564"), "%64");
    }

    #[test]
    fn percent_decode_null_byte() {
        // %00 should decode to a null byte.
        let result = percent_decode("%00");
        assert_eq!(result.len(), 1);
        assert_eq!(result.as_bytes()[0], 0);
    }

    #[test]
    fn percent_decode_ff() {
        // %FF decodes to byte 0xFF, which is invalid UTF-8.
        // String::from_utf8 fails, so the function returns the original input.
        let result = percent_decode("%FF");
        assert_eq!(result, "%FF");
    }

    #[test]
    fn percent_decode_consecutive_percent_signs() {
        assert_eq!(percent_decode("%%"), "%%");
    }

    #[test]
    fn percent_decode_trailing_single_hex() {
        // %4 at end of string: only one nibble, emit literal %4.
        assert_eq!(percent_decode("%4"), "%4");
    }

    #[test]
    fn percent_decode_mixed_valid_and_invalid() {
        // %41 = 'A', %zz is invalid.
        assert_eq!(percent_decode("%41%zz"), "A%zz");
    }

    #[test]
    fn percent_decode_space() {
        // %20 = space.
        assert_eq!(percent_decode("hello%20world"), "hello world");
    }

    // ── hex_digit: boundary values ─────────────────────────────────────

    #[test]
    fn hex_digit_boundaries() {
        // Just outside the digit range.
        assert_eq!(hex_digit(b'/'), None); // one before '0'
        assert_eq!(hex_digit(b':'), None); // one after '9'
                                           // Just outside the lowercase range.
        assert_eq!(hex_digit(b'`'), None); // one before 'a'
                                           // Just outside the uppercase range.
        assert_eq!(hex_digit(b'@'), None); // one before 'A'
    }

    // ── check_request_inputs: path edge cases ──────────────────────────

    #[test]
    fn root_path_allowed() {
        let result = check_request_inputs("/", "", Vec::<(String, String)>::new());
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn empty_path_allowed() {
        let result = check_request_inputs("", "", Vec::<(String, String)>::new());
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn path_with_only_slashes_allowed() {
        let result = check_request_inputs("////", "", Vec::<(String, String)>::new());
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn path_prefix_at_last_segment() {
        let result = check_request_inputs(
            "/v1/challenge/docs-sbx-abc",
            "",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Reject { source: "path" });
    }

    #[test]
    fn path_prefix_at_first_segment_no_leading_slash() {
        let result = check_request_inputs("docs-sbx-abc/v1", "", Vec::<(String, String)>::new());
        assert_eq!(result, PrefixCheck::Reject { source: "path" });
    }

    // ── check_request_inputs: query edge cases ─────────────────────────

    #[test]
    fn query_multiple_params_second_has_prefix() {
        let result = check_request_inputs(
            "/v1/challenge",
            "format=json&token=docs-sbx-abc",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Reject { source: "query" });
    }

    #[test]
    fn query_empty_value_not_matched() {
        // "key=" has an empty value which is skipped.
        let result = check_request_inputs("/v1/challenge", "key=", Vec::<(String, String)>::new());
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn query_multiple_equals_signs() {
        // "key=val=docs-sbx-abc" splits at first '=': key="key", value="val=docs-sbx-abc".
        // The value starts with "val", not a sandbox prefix.
        let result = check_request_inputs(
            "/v1/challenge",
            "key=val=docs-sbx-abc",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn query_ampersand_only_segments_skipped() {
        let result = check_request_inputs("/v1/challenge", "&&&&", Vec::<(String, String)>::new());
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn query_with_bearer_prefix_in_value() {
        // matches_sandbox_prefix strips auth scheme: "Bearer docs-sbx-..." matches.
        let result = check_request_inputs(
            "/v1/challenge",
            "auth=Bearer%20docs-sbx-abc",
            Vec::<(String, String)>::new(),
        );
        // After percent decoding: "Bearer docs-sbx-abc".
        assert_eq!(result, PrefixCheck::Reject { source: "query" });
    }

    // ── check_request_inputs: header edge cases ────────────────────────

    #[test]
    fn mixed_case_header_names_all_inspected() {
        let header_variants = vec![
            ("X-CLIENT-ID", "docs-sbx-abc"),
            ("X-Api-Key", "mwallet-sbx-xyz"),
            ("AUTHORIZATION", "Bearer docs-sbx-token"),
        ];
        for (name, value) in header_variants {
            let headers = vec![(name.to_string(), value.to_string())];
            let result = check_request_inputs("/v1/challenge", "", headers);
            assert_eq!(
                result,
                PrefixCheck::Reject { source: "header" },
                "header name '{}' should be inspected case-insensitively",
                name
            );
        }
    }

    #[test]
    fn multiple_headers_first_match_wins() {
        // Both x-client-id and authorization have sandbox prefixes.
        // The loop iterates in order, so header source is reported.
        let headers = vec![
            ("x-client-id".to_string(), "docs-sbx-first".to_string()),
            (
                "authorization".to_string(),
                "Bearer mwallet-sbx-second".to_string(),
            ),
        ];
        let result = check_request_inputs("/v1/challenge", "", headers);
        assert_eq!(result, PrefixCheck::Reject { source: "header" });
    }

    #[test]
    fn uninspected_headers_with_prefix_pass() {
        // Content-Type, X-Forwarded-For, etc. are not inspected.
        let headers = vec![
            ("content-type".to_string(), "docs-sbx-json".to_string()),
            ("x-forwarded-for".to_string(), "mwallet-sbx-ip".to_string()),
            ("user-agent".to_string(), "docs-sbx-bot".to_string()),
            ("cookie".to_string(), "docs-sbx-session".to_string()),
        ];
        let result = check_request_inputs("/v1/challenge", "", headers);
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn authorization_with_basic_scheme_and_sandbox_prefix() {
        let headers = vec![(
            "authorization".to_string(),
            "Basic docs-sbx-encoded".to_string(),
        )];
        let result = check_request_inputs("/v1/challenge", "", headers);
        assert_eq!(result, PrefixCheck::Reject { source: "header" });
    }

    // ── SANDBOX_PREFIXES constant edge cases ───────────────────────────

    #[test]
    fn sandbox_prefixes_are_lowercase() {
        for prefix in SANDBOX_PREFIXES {
            assert_eq!(
                *prefix,
                prefix.to_lowercase(),
                "prefix '{}' should be lowercase",
                prefix
            );
        }
    }

    #[test]
    fn sandbox_prefixes_contain_sbx() {
        for prefix in SANDBOX_PREFIXES {
            assert!(
                prefix.contains("sbx"),
                "prefix '{}' must contain 'sbx' substring",
                prefix
            );
        }
    }

    // ── REJECTION_BODY constant tests ──────────────────────────────────

    #[test]
    fn rejection_body_has_exactly_two_keys() {
        let parsed: serde_json::Value = serde_json::from_str(REJECTION_BODY).expect("valid JSON"); // nosemgrep: provii.workers.expect-on-external-input
        let obj = parsed.as_object().expect("top-level object");
        assert_eq!(obj.len(), 2);
    }

    #[test]
    fn rejection_body_compact_json() {
        // The body should be compact JSON with no structural whitespace
        // (no spaces around colons or after commas). The string value
        // "Access denied" contains a space, which is fine.
        assert!(!REJECTION_BODY.contains(": "));
        assert!(!REJECTION_BODY.contains(", "));
    }

    // ── Full-request scan: all sources clean ───────────────────────────

    #[test]
    fn all_inputs_clean_passes() {
        let headers = vec![
            ("x-client-id".to_string(), "rp_live_client123".to_string()),
            ("x-api-key".to_string(), "pk_live_key456".to_string()),
            (
                "authorization".to_string(),
                "Bearer pk_live_token789".to_string(),
            ),
        ];
        let result = check_request_inputs(
            "/v1/challenge/rp_live_client123",
            "format=json&callback=https://example.com",
            headers,
        );
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn all_inputs_tainted_reports_first_source() {
        // Path, query, AND headers all have prefixes. Path is checked first.
        let headers = vec![("x-client-id".to_string(), "docs-sbx-h".to_string())];
        let result = check_request_inputs("/v1/docs-sbx-p", "id=mwallet-sbx-q", headers);
        assert_eq!(result, PrefixCheck::Reject { source: "path" });
    }

    #[test]
    fn percent_encoded_prefix_in_query_key_rejected() {
        let result = check_request_inputs(
            "/v1/challenge",
            "%64ocs-sbx-param=value",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Reject { source: "query" });
    }

    #[test]
    fn authorization_bare_sandbox_token_rejected() {
        let headers = vec![(
            "authorization".to_string(),
            "mwallet-sbx-raw-token".to_string(),
        )];
        let result = check_request_inputs("/v1/challenge", "", headers);
        assert_eq!(result, PrefixCheck::Reject { source: "header" });
    }

    #[test]
    fn x_api_key_with_bearer_prefix_rejected() {
        let headers = vec![(
            "x-api-key".to_string(),
            "Bearer docs-sbx-key123".to_string(),
        )];
        let result = check_request_inputs("/v1/challenge", "", headers);
        assert_eq!(result, PrefixCheck::Reject { source: "header" });
    }

    #[test]
    fn empty_headers_allowed() {
        let result = check_request_inputs(
            "/v1/challenge",
            "format=json",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn query_value_exact_prefix_no_suffix_rejected() {
        let result = check_request_inputs(
            "/v1/challenge",
            "id=docs-sbx-",
            Vec::<(String, String)>::new(),
        );
        assert_eq!(result, PrefixCheck::Reject { source: "query" });
    }

    #[test]
    fn path_segment_substring_match_not_prefix() {
        let result =
            check_request_inputs("/v1/xdocs-sbx-client", "", Vec::<(String, String)>::new());
        assert_eq!(result, PrefixCheck::Allow);
    }
}
