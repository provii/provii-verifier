// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Cross-service golden-vector tests for the canonical HMAC signing message
//! contract.
//!
//! The fixture file `tests/fixtures/canonical_message_vectors.json` is
//! mirrored byte-for-byte into `provii-issuer/tests/fixtures/` and into
//! `provii-demos/demo-web-provii-agegate/test/docs/`. It locks the wire format
//! `{timestamp}:{method}:{path}:{body}:{nonce}` along with a known HMAC
//! key so all three implementations can prove byte-equivalence against
//! the same vectors.
//!
//! Coverage in this file:
//!
//! 1. `verifier_*` vectors drive `create_canonical_message_for_challenge`
//!    with synthesised `CreateChallengeRequest` inputs and assert the
//!    output matches `expected_canonical_bytes_hex` exactly. This locks
//!    the JSON serialisation order produced by `serde_json::json!` with
//!    the `preserve_order` feature (transitively enabled).
//!
//! 2. `shared` vectors that already supply a fully-formed `body` string
//!    are assembled directly and HMAC-verified with the published key.
//!    These cover edge cases (empty body, nested object, 1 KB body)
//!    independent of any service-specific constructor.
//!
//! 3. `attestation_*` vectors drive
//!    `provii_crypto_commons::attestation::DobAttestation::compute_message_bytes`
//!    for both the legacy (no binding) and the v1.1 bound form. These
//!    guard the Blake2s-256 framing against silent
//!    drift.
//!
//! 4. `reject_vectors` are documented but only structurally inspected.
//!    The actual rejection paths live behind request-level validators
//!    (`Authorizer::validate`, deserialisation) tested elsewhere; this
//!    file just asserts the fixture catalogues every documented reject
//!    case so the contract surface stays visible to reviewers.

#![forbid(unsafe_code)]
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used
)]

use hmac::{Hmac, Mac};
use provii_crypto_commons::attestation::DobAttestation;
use provii_verifier::routes::challenge::{
    create_canonical_message_for_challenge, CreateChallengeRequest,
};
use provii_verifier::types::auth::Authorizer;
use provii_verifier::types::strict::{B64Url32, ExpiresIn, PkceMethod, VkId};
use serde::Deserialize;
use sha2::Sha256;
use wasm_bindgen_test::*;

type HmacSha256 = Hmac<Sha256>;

const FIXTURE_BYTES: &str = include_str!("../fixtures/canonical_message_vectors.json");

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    hmac_key_hex: String,
    vectors: Vec<Vector>,
    reject_vectors: Vec<RejectVector>,
    attestation_vectors: Vec<AttestationVector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    test_name: String,
    service_origin: String,
    constructor: String,
    inputs: VectorInputs,
    #[serde(default)]
    expected_canonical_bytes_hex: Option<String>,
    #[serde(default)]
    expected_canonical_length: Option<usize>,
    expected_hmac_hex_with_known_key: String,
}

#[derive(Debug, Deserialize)]
struct VectorInputs {
    timestamp: u64,
    method: String,
    path: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    body_construct: Option<BodyConstruct>,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct BodyConstruct {
    kind: String,
    filler_field: String,
    filler_byte: String,
    filler_count: usize,
}

#[derive(Debug, Deserialize)]
struct RejectVector {
    test_name: String,
    reason: String,
    expected_outcome: String,
}

#[derive(Debug, Deserialize)]
struct AttestationVector {
    test_name: String,
    constructor: String,
    inputs: AttestationInputs,
    expected_message_bytes_hex: String,
}

#[derive(Debug, Deserialize)]
struct AttestationInputs {
    dob_days: i32,
    issuer_id: String,
    timestamp: u64,
    nonce_hex: String,
    session_id: Option<String>,
    client_id: Option<String>,
}

fn load_fixture() -> Fixture {
    serde_json::from_str(FIXTURE_BYTES).expect("fixture JSON must parse")
}

fn assemble_canonical(ts: u64, method: &str, path: &str, body: &str, nonce: &str) -> String {
    format!("{}:{}:{}:{}:{}", ts, method, path, body, nonce)
}

fn materialise_body(inputs: &VectorInputs) -> String {
    if let Some(b) = &inputs.body {
        return b.clone();
    }
    let bc = inputs
        .body_construct
        .as_ref()
        .expect("vector has neither body nor body_construct");
    assert_eq!(bc.kind, "filler_object");
    assert_eq!(bc.filler_byte.len(), 1);
    let filler: String = bc.filler_byte.repeat(bc.filler_count);
    format!("{{\"{}\":\"{}\"}}", bc.filler_field, filler)
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex must decode")
}

fn compute_hmac(key: &[u8], msg: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    hex::encode(mac.finalize().into_bytes())
}

#[wasm_bindgen_test]
fn fixture_schema_version_is_one() {
    let fixture = load_fixture();
    assert_eq!(fixture.schema_version, 1, "fixture schema version drift");
    assert_eq!(
        fixture.hmac_key_hex.len(),
        64,
        "shared HMAC key must be 32 bytes (64 hex chars)"
    );
}

/// Drive the actual `create_canonical_message_for_challenge` constructor
/// with synthesised inputs that match the fixture body byte-exactly. This
/// proves the Rust serde_json `json!` output is locked to the documented
/// order: `code_challenge, method, verifying_key_id, expires_in`.
#[wasm_bindgen_test]
fn verifier_constructor_matches_fixture_simple() {
    let fixture = load_fixture();
    let v = fixture
        .vectors
        .iter()
        .find(|v| v.test_name == "verifier_post_challenge_simple")
        .expect("fixture must contain verifier_post_challenge_simple");

    // 32 bytes of 0x2a -> base64url-no-pad "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio"
    let req = CreateChallengeRequest {
        code_challenge: B64Url32::new([0x2au8; 32]),
        method: PkceMethod::S256,
        verifying_key_id: Some(VkId::new(1).expect("vk_id 1 is non-zero")),
        expires_in: ExpiresIn::new(300),
        authorizer: Authorizer {
            key_id: "test-client".to_string(),
            timestamp: v.inputs.timestamp,
            // hmac/nonce are not part of the canonical message body for this
            // constructor; we set them to plausible values so the struct is
            // valid if it ever flows through downstream validation.
            hmac: "0".repeat(64),
            nonce: v.inputs.nonce.clone(),
        },
    };

    let canonical = create_canonical_message_for_challenge(
        &v.inputs.method,
        &v.inputs.path,
        v.inputs.timestamp,
        &req,
    );
    let canonical_bytes = canonical.into_bytes();
    let expected = hex_decode(
        v.expected_canonical_bytes_hex
            .as_ref()
            .expect("simple vector has expected bytes"),
    );
    assert_eq!(
        canonical_bytes, expected,
        "canonical message bytes drifted from fixture for {}",
        v.test_name
    );

    let key = hex_decode(&fixture.hmac_key_hex);
    let actual_hmac = compute_hmac(&key, &canonical_bytes);
    assert_eq!(
        actual_hmac, v.expected_hmac_hex_with_known_key,
        "HMAC drifted for {}",
        v.test_name
    );
}

#[wasm_bindgen_test]
fn verifier_constructor_matches_fixture_null_vk() {
    let fixture = load_fixture();
    let v = fixture
        .vectors
        .iter()
        .find(|v| v.test_name == "verifier_post_challenge_null_vk")
        .expect("fixture must contain verifier_post_challenge_null_vk");

    // 32 bytes of 0xab -> base64url-no-pad "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s"
    let req = CreateChallengeRequest {
        code_challenge: B64Url32::new([0xabu8; 32]),
        method: PkceMethod::S256,
        verifying_key_id: None,
        expires_in: ExpiresIn::new(120),
        authorizer: Authorizer {
            key_id: "test-client".to_string(),
            timestamp: v.inputs.timestamp,
            hmac: "0".repeat(64),
            nonce: v.inputs.nonce.clone(),
        },
    };

    let canonical = create_canonical_message_for_challenge(
        &v.inputs.method,
        &v.inputs.path,
        v.inputs.timestamp,
        &req,
    );
    let canonical_bytes = canonical.into_bytes();
    let expected = hex_decode(
        v.expected_canonical_bytes_hex
            .as_ref()
            .expect("null_vk vector has expected bytes"),
    );
    assert_eq!(canonical_bytes, expected, "canonical drifted on null vk");

    let key = hex_decode(&fixture.hmac_key_hex);
    let actual_hmac = compute_hmac(&key, &canonical_bytes);
    assert_eq!(actual_hmac, v.expected_hmac_hex_with_known_key);
}

/// Generic vectors that supply a fully-formed `body` string. We assemble
/// `{ts}:{method}:{path}:{body}:{nonce}` directly and HMAC-verify against
/// the published key. This guards the wire-format envelope itself,
/// independent of any service-specific body constructor.
#[wasm_bindgen_test]
fn shared_vectors_assemble_and_hmac() {
    let fixture = load_fixture();
    let key = hex_decode(&fixture.hmac_key_hex);

    for v in fixture
        .vectors
        .iter()
        .filter(|v| v.service_origin == "shared")
    {
        let body = materialise_body(&v.inputs);
        let canonical = assemble_canonical(
            v.inputs.timestamp,
            &v.inputs.method,
            &v.inputs.path,
            &body,
            &v.inputs.nonce,
        );
        let canonical_bytes = canonical.into_bytes();

        if let Some(expected_hex) = &v.expected_canonical_bytes_hex {
            let expected = hex_decode(expected_hex);
            assert_eq!(
                canonical_bytes, expected,
                "shared vector {} canonical bytes drifted",
                v.test_name
            );
        }
        if let Some(expected_len) = v.expected_canonical_length {
            assert_eq!(
                canonical_bytes.len(),
                expected_len,
                "shared vector {} length drifted",
                v.test_name
            );
        }

        let actual_hmac = compute_hmac(&key, &canonical_bytes);
        assert_eq!(
            actual_hmac, v.expected_hmac_hex_with_known_key,
            "shared vector {} HMAC drifted",
            v.test_name
        );
        assert_eq!(v.constructor, "raw_assemble");
    }
}

/// Lock the provii-crypto attestation framing (Blake2s-256, length-prefixed
/// strings, little-endian dob_days/timestamp). This is the message signed
/// by the issuer's Ed25519 key; drift here invalidates every attestation
/// previously signed.
#[wasm_bindgen_test]
fn attestation_compute_message_bytes_matches_fixture() {
    let fixture = load_fixture();
    for av in &fixture.attestation_vectors {
        assert_eq!(
            av.constructor, "DobAttestation::compute_message_bytes",
            "fixture attestation_vectors must reference the provii-crypto helper"
        );
        let nonce_bytes = hex_decode(&av.inputs.nonce_hex);
        assert_eq!(
            nonce_bytes.len(),
            32,
            "nonce must be 32 bytes (64 hex chars)"
        );
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&nonce_bytes);

        let session = av.inputs.session_id.as_deref();
        let client = av.inputs.client_id.as_deref();

        let actual = DobAttestation::compute_message_bytes(
            av.inputs.dob_days,
            &av.inputs.issuer_id,
            av.inputs.timestamp,
            &nonce,
            session,
            client,
        )
        .expect("fixture inputs must be in-range");

        let expected = hex_decode(&av.expected_message_bytes_hex);
        assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "attestation vector {} drifted",
            av.test_name
        );
    }
}

/// Reject vectors are catalogued in the fixture so reviewers can see the
/// full contract surface in one place. The actual rejection paths are
/// covered by request-level validation tests (Authorizer::validate, serde
/// deserialisation, timestamp skew check). Here we only assert each reject
/// vector documents an expected_outcome and a reason.
#[wasm_bindgen_test]
fn reject_vectors_have_documented_outcomes() {
    let fixture = load_fixture();
    assert!(
        !fixture.reject_vectors.is_empty(),
        "reject_vectors must catalogue at least one negative case"
    );
    for r in &fixture.reject_vectors {
        assert!(!r.test_name.is_empty(), "reject vector missing test_name");
        assert!(
            !r.reason.is_empty(),
            "reject vector {} missing reason",
            r.test_name
        );
        assert!(
            !r.expected_outcome.is_empty(),
            "reject vector {} missing expected_outcome",
            r.test_name
        );
    }
}

/// Belt-and-braces sanity check: every vector that supplies an
/// `expected_canonical_bytes_hex` field must round-trip through
/// HMAC-SHA-256 and produce the published HMAC. Catches mistyped fixtures.
#[wasm_bindgen_test]
fn every_published_canonical_byte_string_round_trips_hmac() {
    let fixture = load_fixture();
    let key = hex_decode(&fixture.hmac_key_hex);
    let mut checked = 0;
    for v in &fixture.vectors {
        if let Some(expected_hex) = &v.expected_canonical_bytes_hex {
            let bytes = hex_decode(expected_hex);
            let actual = compute_hmac(&key, &bytes);
            assert_eq!(
                actual, v.expected_hmac_hex_with_known_key,
                "fixture round-trip failure for {}",
                v.test_name
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 4,
        "expected at least 4 byte-string vectors, got {checked}"
    );
}
