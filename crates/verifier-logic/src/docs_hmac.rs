// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Docs-gateway HMAC verification (pure logic).
//!
//! Recomputes HMAC-SHA-256 over a request body and constant-time compares
//! it against a hex-encoded tag from the `X-Docs-Hmac` header. Defence in
//! depth for the sandbox docs gateway service binding.
//!
//! SECURITY: All tag comparisons use `hmac::Mac::verify_slice()` which
//! performs constant-time comparison internally.
#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Header the docs gateway writes the hex tag into.
pub const DOCS_HMAC_HEADER: &str = "X-Docs-Hmac";

/// Stable error code returned on any verification failure.
pub const DOCS_HMAC_REJECTION_CODE: &str = "docs_hmac_invalid";

/// Outcome of a verification attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum DocsHmacCheck {
    /// Header present and the recomputed tag matched.
    Ok,
    /// Header missing or empty.
    MissingHeader,
    /// Header present but hex decode failed.
    MalformedHeader,
    /// Header present, decoded, but the tag did not match.
    Mismatch,
}

/// Fail-closed pre-check: verify the cached HMAC key is present and non-empty.
pub fn verify_or_reject_hmac_key(cached: Option<&[u8]>) -> Result<&[u8], DocsHmacCheck> {
    match cached {
        Some(k) if !k.is_empty() => Ok(k),
        _ => Err(DocsHmacCheck::MissingHeader),
    }
}

/// Recompute the HMAC over `body` using `key` and compare constant-time
/// against the hex-decoded `header_value`.
///
/// SECURITY: Uses `hmac::Mac::verify_slice()` for constant-time comparison.
pub fn verify_docs_hmac(header_value: Option<&str>, body: &[u8], key: &[u8]) -> DocsHmacCheck {
    let header = match header_value {
        Some(h) if !h.is_empty() => h,
        _ => return DocsHmacCheck::MissingHeader,
    };

    let supplied_tag = match hex::decode(header) {
        Ok(bytes) => bytes,
        Err(_) => return DocsHmacCheck::MalformedHeader,
    };

    if key.is_empty() {
        return DocsHmacCheck::Mismatch;
    }

    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return DocsHmacCheck::Mismatch,
    };
    mac.update(body);

    // SECURITY: verify_slice runs a constant-time comparison internally.
    match mac.verify_slice(&supplied_tag) {
        Ok(()) => DocsHmacCheck::Ok,
        Err(_) => DocsHmacCheck::Mismatch,
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod tests {
    use super::*;

    fn compute_tag_hex(key: &[u8], body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn accepts_matching_hex_tag() {
        let key = b"SANDBOX_API_KEY";
        let body = br#"{"origin":"https://docs.example.com"}"#;
        let tag = compute_tag_hex(key, body);
        assert_eq!(verify_docs_hmac(Some(&tag), body, key), DocsHmacCheck::Ok);
    }

    #[test]
    fn rejects_missing_header() {
        assert_eq!(
            verify_docs_hmac(None, b"{}", b"SANDBOX_API_KEY"),
            DocsHmacCheck::MissingHeader
        );
    }

    #[test]
    fn rejects_empty_header_value() {
        assert_eq!(
            verify_docs_hmac(Some(""), b"{}", b"SANDBOX_API_KEY"),
            DocsHmacCheck::MissingHeader
        );
    }

    #[test]
    fn rejects_non_hex_header() {
        assert_eq!(
            verify_docs_hmac(Some("not-hex-at-all!"), b"{}", b"SANDBOX_API_KEY"),
            DocsHmacCheck::MalformedHeader
        );
    }

    #[test]
    fn rejects_odd_length_hex() {
        assert_eq!(
            verify_docs_hmac(Some("abc"), b"{}", b"SANDBOX_API_KEY"),
            DocsHmacCheck::MalformedHeader
        );
    }

    #[test]
    fn rejects_wrong_key_tag() {
        let body = b"{}";
        let tag = compute_tag_hex(b"WRONG_KEY", body);
        assert_eq!(
            verify_docs_hmac(Some(&tag), body, b"RIGHT_KEY"),
            DocsHmacCheck::Mismatch
        );
    }

    #[test]
    fn rejects_tampered_body() {
        let key = b"SANDBOX_API_KEY";
        let tag = compute_tag_hex(key, b"{\"origin\":\"a\"}");
        assert_eq!(
            verify_docs_hmac(Some(&tag), b"{\"origin\":\"b\"}", key),
            DocsHmacCheck::Mismatch
        );
    }

    #[test]
    fn rejects_truncated_tag() {
        let key = b"SANDBOX_API_KEY";
        let body = b"{}";
        let mut tag = compute_tag_hex(key, body);
        tag.truncate(20);
        assert_eq!(
            verify_docs_hmac(Some(&tag), body, key),
            DocsHmacCheck::Mismatch
        );
    }

    #[test]
    fn rejects_empty_key() {
        let body = b"{}";
        let tag = compute_tag_hex(b"any", body);
        assert_eq!(
            verify_docs_hmac(Some(&tag), body, b""),
            DocsHmacCheck::Mismatch
        );
    }

    #[test]
    fn verify_or_reject_hmac_key_rejects_none() {
        assert_eq!(
            verify_or_reject_hmac_key(None).unwrap_err(),
            DocsHmacCheck::MissingHeader
        );
    }

    #[test]
    fn verify_or_reject_hmac_key_rejects_empty_slice() {
        assert_eq!(
            verify_or_reject_hmac_key(Some(&[])).unwrap_err(),
            DocsHmacCheck::MissingHeader
        );
    }

    #[test]
    fn verify_or_reject_hmac_key_accepts_populated() {
        let key = b"secret";
        assert_eq!(verify_or_reject_hmac_key(Some(key)).unwrap(), key);
    }

    #[test]
    fn tag_is_body_bound() {
        let key = b"k";
        let a = b"{\"x\":1}";
        let b = b"{\"x\":2}";
        let tag_a = compute_tag_hex(key, a);
        assert_eq!(verify_docs_hmac(Some(&tag_a), a, key), DocsHmacCheck::Ok);
        assert_eq!(
            verify_docs_hmac(Some(&tag_a), b, key),
            DocsHmacCheck::Mismatch
        );
    }

    #[test]
    fn header_constant_value() {
        assert_eq!(DOCS_HMAC_HEADER, "X-Docs-Hmac");
    }

    #[test]
    fn rejection_code_constant_value() {
        assert_eq!(DOCS_HMAC_REJECTION_CODE, "docs_hmac_invalid");
    }

    #[test]
    fn accepts_empty_body_with_valid_tag() {
        let key = b"SANDBOX_API_KEY";
        let body = b"";
        let tag = compute_tag_hex(key, body);
        assert_eq!(verify_docs_hmac(Some(&tag), body, key), DocsHmacCheck::Ok);
    }

    #[test]
    fn accepts_binary_body_with_null_bytes() {
        let key = b"SANDBOX_API_KEY";
        let body: &[u8] = &[0x00, 0x01, 0xFF, 0xFE, 0x00];
        let tag = compute_tag_hex(key, body);
        assert_eq!(verify_docs_hmac(Some(&tag), body, key), DocsHmacCheck::Ok);
    }

    #[test]
    fn accepts_uppercase_hex_header() {
        let key = b"SANDBOX_API_KEY";
        let body = b"{}";
        let tag_lower = compute_tag_hex(key, body);
        let tag_upper = tag_lower.to_uppercase();
        assert_eq!(
            verify_docs_hmac(Some(&tag_upper), body, key),
            DocsHmacCheck::Ok
        );
    }

    #[test]
    fn rejects_tag_with_appended_bytes() {
        let key = b"SANDBOX_API_KEY";
        let body = b"{}";
        let mut tag = compute_tag_hex(key, body);
        tag.push_str("deadbeef");
        assert_eq!(
            verify_docs_hmac(Some(&tag), body, key),
            DocsHmacCheck::Mismatch
        );
    }

    #[test]
    fn rejects_whitespace_only_header() {
        assert_eq!(
            verify_docs_hmac(Some("   "), b"{}", b"SANDBOX_API_KEY"),
            DocsHmacCheck::MalformedHeader
        );
    }

    #[test]
    fn long_key_accepted() {
        let key = vec![0xABu8; 256];
        let body = b"long-key-test";
        let tag = compute_tag_hex(&key, body);
        assert_eq!(verify_docs_hmac(Some(&tag), body, &key), DocsHmacCheck::Ok);
    }

    #[test]
    fn large_body_accepted() {
        let key = b"SANDBOX_API_KEY";
        let body = vec![b'X'; 1_000_000];
        let tag = compute_tag_hex(key, &body);
        assert_eq!(verify_docs_hmac(Some(&tag), &body, key), DocsHmacCheck::Ok);
    }

    #[test]
    fn tag_hex_is_64_chars() {
        let tag = compute_tag_hex(b"key", b"body");
        assert_eq!(tag.len(), 64);
        assert!(tag.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_keys_produce_different_tags() {
        let body = b"same-body";
        let tag1 = compute_tag_hex(b"key-alpha", body);
        let tag2 = compute_tag_hex(b"key-bravo", body);
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn tag_is_deterministic() {
        let key = b"deterministic-key";
        let body = b"deterministic-body";
        let tag1 = compute_tag_hex(key, body);
        let tag2 = compute_tag_hex(key, body);
        assert_eq!(tag1, tag2);
    }

    // AAD/domain-sep regression: the provii-verifier domain tags must be
    // preserved exactly. The docs HMAC does not use domain tags itself, but
    // this test anchors the constant values that routes depend on.
    #[test]
    fn constants_are_stable_regression() {
        assert_eq!(DOCS_HMAC_HEADER, "X-Docs-Hmac");
        assert_eq!(DOCS_HMAC_REJECTION_CODE, "docs_hmac_invalid");
    }
}
