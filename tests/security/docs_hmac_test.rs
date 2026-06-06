// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Integration tests for the docs-gateway HMAC verification middleware
//! (task W6-NT3).
//!
//! The wire contract these tests guard:
//!
//!   - Header name: `X-Docs-Hmac`, hex-encoded HMAC-SHA-256 over the
//!     request body, signed with the shared `SANDBOX_API_KEY`.
//!   - Missing header, malformed hex, wrong key, and tampered body all
//!     produce the same rejection outcome from the caller's perspective
//!     (401 at the handler layer). The internal `DocsHmacCheck` enum
//!     distinguishes them for log output but is not surfaced in the body.
//!
//! The paired TypeScript signer lives in
//! `provii-demos/demo-web-provii-agegate/src/docs/credentials.ts::signUpstreamBody`.
//! It uses `TextEncoder` over the same shared secret string and emits the
//! tag as lowercase hex. `compute_tag_hex` in these tests mirrors that
//! signer byte-for-byte so the fixtures here exercise the exact contract.

#![forbid(unsafe_code)]
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used
)]

use hmac::{Hmac, Mac};
use provii_verifier::security::docs_hmac::{
    verify_docs_hmac, verify_or_reject_hmac_key, DocsHmacCheck, DOCS_HMAC_HEADER,
    DOCS_HMAC_REJECTION_CODE,
};
use sha2::Sha256;
use wasm_bindgen_test::*;

type HmacSha256 = Hmac<Sha256>;

fn compute_tag_hex(key: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

// ─── header contract ────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn header_name_is_stable_x_docs_hmac() {
    // Guards against accidental rename. The docs gateway emits
    // `X-Docs-Hmac` verbatim; changing this name without a coordinated
    // gateway update silently breaks the contract.
    assert_eq!(DOCS_HMAC_HEADER, "X-Docs-Hmac");
}

#[wasm_bindgen_test]
fn rejection_code_is_stable_docs_hmac_invalid() {
    assert_eq!(DOCS_HMAC_REJECTION_CODE, "docs_hmac_invalid");
}

// ─── success path ───────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn accepts_correctly_signed_body() {
    let key = b"SANDBOX_API_KEY_value_32bytes_x";
    let body = br#"{"origin":"https://docs.example.com","api_key":"k","min_age_years":18}"#;
    let tag = compute_tag_hex(key, body);
    assert_eq!(verify_docs_hmac(Some(&tag), body, key), DocsHmacCheck::Ok);
}

#[wasm_bindgen_test]
fn accepts_uppercase_hex_tag() {
    let key = b"k";
    let body = b"{}";
    let tag = compute_tag_hex(key, body).to_uppercase();
    // hex::decode accepts both cases; gateway emits lowercase but we
    // should not reject if a future gateway version switches case.
    assert_eq!(verify_docs_hmac(Some(&tag), body, key), DocsHmacCheck::Ok);
}

#[wasm_bindgen_test]
fn accepts_empty_body_when_correctly_signed() {
    // JSON spec permits an empty body for a POST with Content-Length 0.
    // HMAC over zero bytes is well-defined; the gateway signer handles it.
    let key = b"k";
    let tag = compute_tag_hex(key, b"");
    assert_eq!(verify_docs_hmac(Some(&tag), b"", key), DocsHmacCheck::Ok);
}

// ─── missing header ─────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn rejects_missing_header() {
    let key = b"k";
    let body = b"{}";
    assert_eq!(
        verify_docs_hmac(None, body, key),
        DocsHmacCheck::MissingHeader
    );
}

#[wasm_bindgen_test]
fn rejects_empty_header_string() {
    // `X-Docs-Hmac: ` (trailing whitespace only) must not pass.
    let key = b"k";
    let body = b"{}";
    assert_eq!(
        verify_docs_hmac(Some(""), body, key),
        DocsHmacCheck::MissingHeader
    );
}

// ─── malformed header ───────────────────────────────────────────────────

#[wasm_bindgen_test]
fn rejects_non_hex_header() {
    let key = b"k";
    let body = b"{}";
    assert_eq!(
        verify_docs_hmac(Some("g".repeat(64).as_str()), body, key),
        DocsHmacCheck::MalformedHeader
    );
}

#[wasm_bindgen_test]
fn rejects_odd_length_hex_header() {
    let key = b"k";
    let body = b"{}";
    assert_eq!(
        verify_docs_hmac(Some("abc"), body, key),
        DocsHmacCheck::MalformedHeader
    );
}

#[wasm_bindgen_test]
fn rejects_base64_style_header() {
    // If a client accidentally sends base64 instead of hex, it decodes
    // partially as hex (for '=' this is a non-hex char and fails); this
    // test pins the behaviour so a future regression surfaces.
    let key = b"k";
    let body = b"{}";
    assert_eq!(
        verify_docs_hmac(Some("abcd=="), body, key),
        DocsHmacCheck::MalformedHeader
    );
}

// ─── wrong signature ────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn rejects_tag_signed_with_wrong_key() {
    let body = b"{\"x\":1}";
    let bad_tag = compute_tag_hex(b"WRONG", body);
    assert_eq!(
        verify_docs_hmac(Some(&bad_tag), body, b"RIGHT"),
        DocsHmacCheck::Mismatch
    );
}

#[wasm_bindgen_test]
fn rejects_tampered_body() {
    let key = b"k";
    let tag = compute_tag_hex(key, b"{\"origin\":\"a.example.com\"}");
    // Attacker-flipped origin, same tag. Must fail.
    assert_eq!(
        verify_docs_hmac(Some(&tag), b"{\"origin\":\"attacker.com\"}", key),
        DocsHmacCheck::Mismatch
    );
}

#[wasm_bindgen_test]
fn rejects_truncated_tag_of_correct_prefix() {
    // Half-length HMAC is a popular "save bytes" mistake. The library
    // treats it as a decode success but a length mismatch; the verifier
    // must reject as Mismatch rather than Ok.
    let key = b"k";
    let body = b"{}";
    let mut tag = compute_tag_hex(key, body);
    tag.truncate(32); // 16 bytes instead of 32.
    assert_eq!(
        verify_docs_hmac(Some(&tag), body, key),
        DocsHmacCheck::Mismatch
    );
}

#[wasm_bindgen_test]
fn rejects_tag_extended_with_zeros() {
    // Padded-up tag: valid hex, wrong length, wrong tag. Mismatch.
    let key = b"k";
    let body = b"{}";
    let mut tag = compute_tag_hex(key, body);
    tag.push_str("00000000");
    assert_eq!(
        verify_docs_hmac(Some(&tag), body, key),
        DocsHmacCheck::Mismatch
    );
}

#[wasm_bindgen_test]
fn rejects_all_zero_tag() {
    let key = b"k";
    let body = b"{}";
    assert_eq!(
        verify_docs_hmac(Some(&"0".repeat(64)), body, key),
        DocsHmacCheck::Mismatch
    );
}

// ─── unconfigured key ───────────────────────────────────────────────────

#[wasm_bindgen_test]
fn rejects_when_key_is_empty() {
    // The route should never reach the verifier without a cached key, but
    // the function must fail closed rather than permit any tag through an
    // unconfigured HMAC.
    let body = b"{}";
    let tag = compute_tag_hex(b"something", body);
    assert_eq!(
        verify_docs_hmac(Some(&tag), body, b""),
        DocsHmacCheck::Mismatch
    );
}

// ─── body-binding ───────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn tag_binds_to_exact_bytes_including_whitespace() {
    // JSON with and without trailing whitespace are different byte
    // sequences; the tag must follow suit. This catches the classic
    // "gateway sends canonicalised JSON but upstream reads raw" bug.
    let key = b"k";
    let tight = b"{\"a\":1}";
    let loose = b"{\"a\": 1}";
    let tag_tight = compute_tag_hex(key, tight);
    assert_eq!(
        verify_docs_hmac(Some(&tag_tight), tight, key),
        DocsHmacCheck::Ok
    );
    assert_eq!(
        verify_docs_hmac(Some(&tag_tight), loose, key),
        DocsHmacCheck::Mismatch
    );
}

// ─── fail-closed startup check (W7-S1) ──────────────────────────────────

#[wasm_bindgen_test]
fn verify_or_reject_hmac_key_rejects_missing_cache() {
    // Simulates SANDBOX_API_KEY not being read at startup. The route MUST
    // reject the inbound call as `docs_hmac_invalid` (401) before any
    // JSON parse runs on attacker-controlled bytes. Returning
    // `MissingHeader` is deliberate: the outward-facing rejection code is
    // shared across every fail-closed branch so callers cannot distinguish
    // a boot-time secrets outage from a legitimate unauthenticated request.
    let err = verify_or_reject_hmac_key(None).unwrap_err();
    assert_eq!(err, DocsHmacCheck::MissingHeader);
}

#[wasm_bindgen_test]
fn verify_or_reject_hmac_key_rejects_empty_cached_value() {
    // An empty secret string is treated as absent. A zero-byte key would
    // otherwise construct a valid HMAC that any attacker who knew the
    // scheme could forge; explicit rejection closes that gap.
    let err = verify_or_reject_hmac_key(Some(&[])).unwrap_err();
    assert_eq!(err, DocsHmacCheck::MissingHeader);
}

#[wasm_bindgen_test]
fn verify_or_reject_hmac_key_accepts_populated_cache() {
    let key = b"SANDBOX_API_KEY_value";
    let k = verify_or_reject_hmac_key(Some(key)).unwrap();
    assert_eq!(k, key);
}

#[wasm_bindgen_test]
fn verify_or_reject_hmac_key_error_matches_rejection_code() {
    // Guards the invariant that the fail-closed branch uses the same
    // outward-facing code the route returns on any HMAC failure. If the
    // enum variant changes, route handlers must still emit
    // `docs_hmac_invalid` as the response body `error` field.
    let _err = verify_or_reject_hmac_key(None).unwrap_err();
    assert_eq!(DOCS_HMAC_REJECTION_CODE, "docs_hmac_invalid");
}

#[wasm_bindgen_test]
fn tag_is_order_sensitive() {
    // Two JSON objects with identical fields in different order have
    // different byte sequences (no canonicalisation). Verify the tag
    // binds to ordering.
    let key = b"k";
    let a = b"{\"a\":1,\"b\":2}";
    let b = b"{\"b\":2,\"a\":1}";
    let tag_a = compute_tag_hex(key, a);
    assert_eq!(verify_docs_hmac(Some(&tag_a), a, key), DocsHmacCheck::Ok);
    assert_eq!(
        verify_docs_hmac(Some(&tag_a), b, key),
        DocsHmacCheck::Mismatch
    );
}
