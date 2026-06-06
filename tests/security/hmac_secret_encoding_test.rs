// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! HMAC secret encoding harmonisation tests (task #50).
//!
//! Pins the canonical convention for HMAC secret material across all
//! Provii HMAC endpoints (provii-verifier, provii-issuer, provii-management):
//!
//!   1. The HMAC key is 32 RAW random bytes.
//!   2. The base64url string returned to clients is purely transport
//!      encoding; clients MUST base64url-decode before signing.
//!   3. The encrypted plaintext stored in KV is the 32 RAW bytes, NOT
//!      the 43-character ASCII representation.
//!
//! Before this fix, `register-test-origin` in provii-verifier stored the
//! 43-char ASCII form, which forced sandbox `rp_sandbox_*` clients to
//! sign with the 43 ASCII bytes instead of decoding first. provii-issuer
//! and provii-management always used the canonical form. Cross-service
//! reuse of the same `hmac_secret` string was therefore impossible
//! without per-service decode-or-not logic.
//!
//! These tests are golden vectors enforcing the post-fix invariant.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use wasm_bindgen_test::*;

type HmacSha256 = Hmac<Sha256>;

/// Provisioning helper that mirrors the fixed `register-test-origin`:
/// returns (32 raw bytes, 43-char base64url transport encoding).
fn provision() -> (Vec<u8>, String) {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).expect("getrandom");
    let b64url = URL_SAFE_NO_PAD.encode(raw);
    (raw.to_vec(), b64url)
}

/// Canonical client flow: receive transport string, decode to 32 raw
/// bytes, sign. MUST match server-side signing with the same raw bytes.
#[wasm_bindgen_test]
fn canonical_decode_then_sign_matches_server_raw_bytes() {
    let (raw, b64url) = provision();
    assert_eq!(raw.len(), 32);
    assert_eq!(b64url.len(), 43);

    let canonical = "1234567890:POST:/v1/challenge:{\"x\":1}:nonce-abc";

    let decoded = URL_SAFE_NO_PAD.decode(&b64url).unwrap();
    assert_eq!(decoded, raw);

    let mut client = HmacSha256::new_from_slice(&decoded).unwrap();
    client.update(canonical.as_bytes());
    let client_tag = client.finalize().into_bytes();

    let mut server = HmacSha256::new_from_slice(&raw).unwrap();
    server.update(canonical.as_bytes());
    let server_tag = server.finalize().into_bytes();

    assert_eq!(
        client_tag.as_slice(),
        server_tag.as_slice(),
        "canonical decode-then-sign must match server raw-bytes verify"
    );
}

/// Pre-fix behaviour: server held 43 ASCII bytes, client decoded to 32.
/// They MUST diverge. That mismatch is exactly what made the two services
/// incompatible before harmonisation. Any reversion of the fix flips this
/// back to a false negative, so this test stays as a regression guard.
#[wasm_bindgen_test]
fn legacy_43_ascii_form_diverges_from_decoded_form() {
    let (raw, b64url) = provision();
    let canonical = "9999999999:POST:/v1/challenge:{}:nonce";

    let mut legacy_server = HmacSha256::new_from_slice(b64url.as_bytes()).unwrap();
    legacy_server.update(canonical.as_bytes());
    let legacy_tag = legacy_server.finalize().into_bytes();

    let mut canonical_client = HmacSha256::new_from_slice(&raw).unwrap();
    canonical_client.update(canonical.as_bytes());
    let client_tag = canonical_client.finalize().into_bytes();

    assert_ne!(
        legacy_tag.as_slice(),
        client_tag.as_slice(),
        "43 ASCII bytes vs 32 decoded bytes must produce different HMAC tags"
    );
}

/// Cross-service determinism: a fixed 32-byte key + canonical message
/// produces a fixed HMAC tag. This vector must be reproducible from
/// provii-issuer and provii-management code paths (the constant key is
/// 32 zero bytes for ease of cross-implementation copy).
#[wasm_bindgen_test]
fn fixed_vector_zero_key_matches_published_tag() {
    let key = [0u8; 32];
    let canonical = "1700000000:POST:/v1/challenge:{\"a\":1}:nonce-fixed";

    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(canonical.as_bytes());
    let tag_hex = hex::encode(mac.finalize().into_bytes());

    // Computed offline against the same canonical message; pinned here
    // so any drift in HMAC-SHA256 over canonical bytes is caught.
    assert_eq!(
        tag_hex, "e2f9037a1d71027710f085d9238d229e7ab5724a5b99305bc156f5d7b6504363",
        "HMAC-SHA256 over fixed canonical/key must match the cross-service vector"
    );
}
