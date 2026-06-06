// Copyright (c) 2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust (ABN 61 633 823 792)
// SPDX-License-Identifier: AGPL-3.0-only

//! ADV-VA-06-009: Fuzz target refocused on provii-verifier's HMAC auth code paths.
//!
//! Exercises `verify_docs_hmac` and `verify_or_reject_hmac_key` from the
//! `security::docs_hmac` module with arbitrary inputs. This validates that
//! the provii-verifier's parsing, hex decoding, and constant-time comparison
//! handle malformed data without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_verifier::security::docs_hmac::{
    verify_docs_hmac, verify_or_reject_hmac_key, DocsHmacCheck,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Split fuzzer data into key, body, and header segments.
    let split1 = data.len() / 3;
    let split2 = (data.len() * 2) / 3;
    let key = &data[..split1];
    let body = &data[split1..split2];
    let header_bytes = &data[split2..];

    // Test 1: verify_docs_hmac with arbitrary hex-like header values.
    // The function must never panic regardless of input.
    if let Ok(header_str) = std::str::from_utf8(header_bytes) {
        let result = verify_docs_hmac(Some(header_str), body, key);
        // Must always return a valid variant.
        match result {
            DocsHmacCheck::Ok
            | DocsHmacCheck::MissingHeader
            | DocsHmacCheck::MalformedHeader
            | DocsHmacCheck::Mismatch => {}
        }
    }

    // Test 2: verify_docs_hmac with None header.
    let result = verify_docs_hmac(None, body, key);
    assert!(
        result == DocsHmacCheck::MissingHeader,
        "None header must produce MissingHeader"
    );

    // Test 3: verify_docs_hmac with empty header string.
    let result = verify_docs_hmac(Some(""), body, key);
    assert!(
        result == DocsHmacCheck::MissingHeader,
        "Empty header must produce MissingHeader"
    );

    // Test 4: verify_or_reject_hmac_key with fuzzer key.
    let _ = verify_or_reject_hmac_key(Some(key));
    let _ = verify_or_reject_hmac_key(None);
    let _ = verify_or_reject_hmac_key(Some(&[]));

    // Test 5: Compute a valid HMAC and verify it roundtrips.
    // This exercises the happy path with fuzzer-generated keys and bodies.
    if !key.is_empty() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        if let Ok(mut mac) = HmacSha256::new_from_slice(key) {
            mac.update(body);
            let valid_tag = hex::encode(mac.finalize().into_bytes());
            let result = verify_docs_hmac(Some(&valid_tag), body, key);
            assert!(
                result == DocsHmacCheck::Ok,
                "Valid HMAC must produce Ok"
            );
        }
    }

    // Test 6: Verify that a bit-flipped tag is rejected.
    if !key.is_empty() && !body.is_empty() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        if let Ok(mut mac) = HmacSha256::new_from_slice(key) {
            mac.update(body);
            let mut tag_bytes = mac.finalize().into_bytes().to_vec();
            tag_bytes[0] ^= 0x01; // flip one bit
            let flipped_tag = hex::encode(&tag_bytes);
            let result = verify_docs_hmac(Some(&flipped_tag), body, key);
            assert!(
                result == DocsHmacCheck::Mismatch,
                "Bit-flipped tag must produce Mismatch"
            );
        }
    }

    // Test 7: Exercise with raw bytes as hex header (may or may not parse).
    let raw_hex = hex::encode(header_bytes);
    let result = verify_docs_hmac(Some(&raw_hex), body, key);
    match result {
        DocsHmacCheck::Ok
        | DocsHmacCheck::MissingHeader
        | DocsHmacCheck::MalformedHeader
        | DocsHmacCheck::Mismatch => {}
    }
});
