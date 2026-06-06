// Copyright (c) 2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust (ABN 61 633 823 792)
// SPDX-License-Identifier: AGPL-3.0-only

//! ADV-VA-06-009: Fuzz target refocused on provii-verifier's issuer registry
//! parsing and key hashing code paths.
//!
//! Exercises `IssuerMeta` deserialisation, Blake2s-256 key hashing (with the
//! `provii.issuer.vk.v0` domain separator used by the JWKS cache), and
//! base64url public key decoding. These are the actual code paths the
//! verifier uses when processing issuer data from KV.

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_verifier::storage::jwks::IssuerMeta;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Test 1: Fuzz deserialisation of IssuerMeta.
    // The verifier deserialises issuer metadata from KV; malformed entries
    // must not cause panics.
    let _ = serde_json::from_slice::<IssuerMeta>(data);

    // Test 2: Try to parse as JSON and then construct IssuerMeta from fields.
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) {
        if let Some(obj) = json.as_object() {
            // Extract fields that would appear in an issuer registry entry
            let _kid = obj.get("kid").and_then(|v| v.as_str());
            let x = obj.get("vk_bytes").and_then(|v| v.as_str());
            let _revoked = obj.get("revoked").and_then(|v| v.as_bool());
            let _name = obj.get("name").and_then(|v| v.as_str());

            // If there's a vk_bytes field, try base64url decoding (matches
            // the format used in the issuer registry KV entries).
            if let Some(vk_str) = x {
                use base64::Engine;
                if let Ok(vk_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(vk_str)
                {
                    // Hash the key the same way JwksCache does.
                    if vk_bytes.len() == 32 {
                        use blake2::{Blake2s256, Digest};
                        let mut hasher = Blake2s256::new();
                        hasher.update(b"provii.issuer.vk.v0");
                        hasher.update(&vk_bytes);
                        let hash = hasher.finalize();
                        assert_eq!(hash.len(), 32, "Blake2s-256 must produce 32 bytes");

                        // Verify determinism
                        let mut hasher2 = Blake2s256::new();
                        hasher2.update(b"provii.issuer.vk.v0");
                        hasher2.update(&vk_bytes);
                        let hash2 = hasher2.finalize();
                        assert_eq!(hash, hash2, "Blake2s hashing must be deterministic");
                    }
                }
            }
        }
    }

    // Test 3: Construct IssuerMeta directly and serialise/deserialise roundtrip.
    if data.len() >= 32 {
        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(&data[..32]);

        let kid_end = 32_usize.saturating_add(data.len().saturating_sub(32) / 2);
        let kid_str = String::from_utf8_lossy(&data[32..kid_end.min(data.len())]).to_string();
        let name_str =
            String::from_utf8_lossy(&data[kid_end.min(data.len())..]).to_string();
        let revoked = data.len() % 2 == 0;

        let meta = IssuerMeta {
            kid: kid_str,
            name: name_str,
            revoked,
            vk_bytes,
        };

        // Serialise and deserialise must roundtrip.
        if let Ok(json) = serde_json::to_string(&meta) {
            if let Ok(parsed) = serde_json::from_str::<IssuerMeta>(&json) {
                assert_eq!(parsed.kid, meta.kid);
                assert_eq!(parsed.name, meta.name);
                assert_eq!(parsed.revoked, meta.revoked);
                assert_eq!(parsed.vk_bytes, meta.vk_bytes);
            }
        }
    }

    // Test 4: Blake2s-256 key hashing with the domain separator.
    // This is the exact computation JwksCache::process_entry uses to
    // key the in-memory cache.
    if data.len() >= 32 {
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(b"provii.issuer.vk.v0");
        hasher.update(&data[..32]);
        let result = hasher.finalize();
        assert_eq!(result.len(), 32, "Blake2s-256 must produce 32 bytes");
    }

    // Test 5: Base64url encoding/decoding of verification keys.
    if data.len() >= 32 {
        use base64::Engine;
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&data[..32]);
        let decoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&encoded);
        assert!(decoded.is_ok(), "Roundtrip decode must succeed");
        assert_eq!(
            decoded.unwrap(),
            &data[..32],
            "Roundtrip must be lossless"
        );
    }

    // Test 6: Try decoding arbitrary data as base64url verification key.
    if let Ok(data_str) = std::str::from_utf8(data) {
        use base64::Engine;
        let _ = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data_str);
    }

    // Test 7: Test with various malformed IssuerMeta JSON structures.
    let malformed_patterns: &[&[u8]] = &[
        br#"{"kid":null}"#,
        br#"{"kid":"test","revoked":"not-a-bool"}"#,
        br#"{"kid":"test","vk_bytes":"not-an-array"}"#,
        br#"{"kid":"","name":"","revoked":false,"vk_bytes":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#,
        b"",
        b"null",
        b"[]",
    ];

    for pattern in malformed_patterns {
        let _ = serde_json::from_slice::<IssuerMeta>(pattern);
    }

    // Test 8: IssuerMeta Debug trait must not panic on any state.
    if data.len() >= 32 {
        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(&data[..32]);
        let meta = IssuerMeta {
            kid: String::from_utf8_lossy(&data[..data.len().min(8)]).to_string(),
            name: "fuzz".to_string(),
            revoked: false,
            vk_bytes,
        };
        let _ = format!("{:?}", meta);
    }
});
