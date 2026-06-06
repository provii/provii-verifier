// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Integration tests for the sandbox-prefix rejection middleware
//!.
//!
//! The middleware operates purely on URL path, query string, and a
//! fixed set of request headers; no AppState, KV, or Durable Objects
//! are required, so all cases can be exercised through the pure
//! `check_request_inputs` entry point re-exported by `security::mod`.
//!
//! This file deliberately mirrors the shape of the provii-management test
//! suite (`provii-management/tests/prefix-rejection.test.ts`) so the two
//! implementations can be diffed side-by-side when one diverges.

#![forbid(unsafe_code)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use provii_verifier::security::prefix_rejection::{check_request_inputs, PrefixCheck};
use wasm_bindgen_test::*;

fn hdrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

// ─── allow: legitimate traffic ─────────────────────────────────────────

#[wasm_bindgen_test]
fn allows_legitimate_verifier_request() {
    let result = check_request_inputs(
        "/v1/verify",
        "client_id=real-client",
        hdrs(&[("x-client-id", "real-client"), ("x-api-key", "sk_live_abc")]),
    );
    assert_eq!(result, PrefixCheck::Allow);
}

#[wasm_bindgen_test]
fn allows_empty_inputs() {
    let result = check_request_inputs("/", "", vec![]);
    assert_eq!(result, PrefixCheck::Allow);
}

#[wasm_bindgen_test]
fn allows_path_with_empty_segments() {
    let result = check_request_inputs("//v1///verify//", "", vec![]);
    assert_eq!(result, PrefixCheck::Allow);
}

#[wasm_bindgen_test]
fn allows_non_inspected_header_even_if_prefixed() {
    // A rogue User-Agent is not a security signal on its own. The
    // check must not over-block.
    let result = check_request_inputs(
        "/v1/verify",
        "",
        hdrs(&[("user-agent", "docs-sbx-ua-bot/1.0")]),
    );
    assert_eq!(result, PrefixCheck::Allow);
}

// ─── reject: path segments ─────────────────────────────────────────────

#[wasm_bindgen_test]
fn rejects_docs_sbx_path_segment() {
    let result = check_request_inputs("/v1/clients/docs-sbx-abc", "", vec![]);
    assert_eq!(result, PrefixCheck::Reject { source: "path" });
}

#[wasm_bindgen_test]
fn rejects_mwallet_sbx_path_segment() {
    let result = check_request_inputs("/v1/clients/mwallet-sbx-xyz", "", vec![]);
    assert_eq!(result, PrefixCheck::Reject { source: "path" });
}

#[wasm_bindgen_test]
fn rejects_percent_encoded_path_prefix() {
    // `docs-sbx-foo` with the `f` encoded as `%66`.
    let result = check_request_inputs("/v1/clients/docs-sbx-%66oo", "", vec![]);
    assert_eq!(result, PrefixCheck::Reject { source: "path" });
}

// ─── reject: query string ──────────────────────────────────────────────

#[wasm_bindgen_test]
fn rejects_sandbox_prefix_in_query_value() {
    let result = check_request_inputs("/v1/verify", "client_id=docs-sbx-q", vec![]);
    assert_eq!(result, PrefixCheck::Reject { source: "query" });
}

#[wasm_bindgen_test]
fn rejects_repeated_query_key_any_match() {
    let result = check_request_inputs("/v1/verify", "id=ok&id=mwallet-sbx-p", vec![]);
    assert_eq!(result, PrefixCheck::Reject { source: "query" });
}

#[wasm_bindgen_test]
fn rejects_key_only_query_entry() {
    // `?docs-sbx-keyonly` with no `=value`.
    let result = check_request_inputs("/v1/verify", "docs-sbx-keyonly", vec![]);
    assert_eq!(result, PrefixCheck::Reject { source: "query" });
}

// ─── reject: identifying headers ───────────────────────────────────────

#[wasm_bindgen_test]
fn rejects_x_client_id_header() {
    let result = check_request_inputs(
        "/v1/verify",
        "",
        hdrs(&[("x-client-id", "docs-sbx-header")]),
    );
    assert_eq!(result, PrefixCheck::Reject { source: "header" });
}

#[wasm_bindgen_test]
fn rejects_x_api_key_header() {
    // Mixed-case header name: middleware normalises to lowercase.
    let result = check_request_inputs(
        "/v1/verify",
        "",
        hdrs(&[("X-API-Key", "mwallet-sbx-apikey")]),
    );
    assert_eq!(result, PrefixCheck::Reject { source: "header" });
}

#[wasm_bindgen_test]
fn rejects_authorization_bearer_token() {
    let result = check_request_inputs(
        "/v1/verify",
        "",
        hdrs(&[("authorization", "Bearer docs-sbx-bearertoken")]),
    );
    assert_eq!(result, PrefixCheck::Reject { source: "header" });
}

#[wasm_bindgen_test]
fn rejects_authorization_raw_token() {
    let result = check_request_inputs("/v1/verify", "", hdrs(&[("authorization", "docs-sbx-raw")]));
    assert_eq!(result, PrefixCheck::Reject { source: "header" });
}
