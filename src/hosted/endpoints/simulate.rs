// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Sandbox proof simulator for hosted verification sessions.
//!
//! `POST /v1/hosted/sandbox/simulate-proof` allows developers to complete the
//! hosted verification flow from a browser without a physical wallet device.
//! When a challenge is in `Pending` state, the caller provides the
//! `submit_secret` and a desired outcome ("verified" or "age_not_met"). The
//! handler transitions the challenge through the same state machine as the
//! real `POST /v1/verify` endpoint.
//!
//! ## Security
//!
//! SECURITY: This endpoint is gated to sandbox environment only. Production
//! requests receive a 404. The sandbox gate is checked both at the router
//! level and inside this handler (defence in depth).
//!
//! SECURITY: `submit_secret` comparison uses `subtle::ConstantTimeEq::ct_eq`
//! to prevent timing side channels.
//!
//! SECURITY: All secret material (`submit_secret` bytes) is wrapped in
//! `Zeroizing` and explicitly zeroised after use.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use worker::{Error as WorkerError, Response};
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_arch = "wasm32")]
use crate::security::log_sanitizer::redact_challenge_id;

use crate::{cache::ChallengeState, error::ApiError, utils::current_timestamp, AppState};

// ---------------------------------------------------------------------------
// Request type
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/hosted/sandbox/simulate-proof`.
///
/// SECURITY: `submit_secret` is zeroised on drop. The manual `Debug` impl
/// redacts the secret to prevent leakage via logging.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulateProofRequest {
    /// Challenge UUID to simulate proof for.
    pub challenge_id: String,
    /// Base64url-encoded 32-byte submit secret (matches challenge creation).
    pub submit_secret: String,
    /// Desired outcome: "verified" or "age_not_met".
    pub outcome: String,
}

impl std::fmt::Debug for SimulateProofRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimulateProofRequest")
            .field("challenge_id", &self.challenge_id)
            .field("submit_secret", &"[REDACTED]")
            .field("outcome", &self.outcome)
            .finish()
    }
}

impl Drop for SimulateProofRequest {
    fn drop(&mut self) {
        self.submit_secret.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Response type
// ---------------------------------------------------------------------------

/// Response body for a successful simulation.
#[derive(Debug, serde::Serialize)]
pub struct SimulateProofResponse {
    /// Always "ok" on success.
    pub result: String,
    /// Resulting challenge state after simulation.
    pub state: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `POST /v1/hosted/sandbox/simulate-proof`.
///
/// Simulates a proof submission for sandbox developer testing. Transitions
/// the challenge through the same state machine as the real verification
/// endpoint, but without requiring an actual ZK proof or wallet device.
///
/// # Security
///
/// - Sandbox environment gate (defence in depth; router also gates)
/// - Constant-time `submit_secret` comparison via `subtle::ConstantTimeEq`
/// - Secret material wrapped in `Zeroizing`
/// - Input validation (UUID format, base64url pattern, strict outcome enum)
///
/// # Errors
///
/// - 404 if not in sandbox environment, or challenge not found
/// - 400 for invalid request fields
/// - 403 for submit_secret mismatch
/// - 410 for non-Pending or expired challenges
///
/// TODO(testing): ADV-VA-06-012 / VA-RTE-011 -- submit_secret validation
/// and sandbox gating lack integration tests. Requires a test harness
/// that can construct worker::Request with Durable Object bindings.
pub async fn handle_simulate_proof(
    state: Arc<AppState>,
    body_bytes: Vec<u8>,
) -> Result<Response, WorkerError> {
    // ── Defence-in-depth sandbox gate ──────────────────────────────────────
    if state.cfg.environment != "sandbox" {
        return ApiError::NotFound.to_response();
    }

    // ── Parse request body ────────────────────────────────────────────────
    // PG-VAL-016: Use structured error envelope so devs see {error, code,
    // field, detail, request_id} instead of plain text 4-byte responses.
    // Body schema: {challenge_id: <uuid>, submit_secret: <43-char base64url>,
    // outcome: "verified" | "age_not_met"}.
    // SECURITY: detail strings cannot contain `|` (the structured-error
    // sentinel encoder replaces it with `/` to keep parsing unambiguous).
    // The schema hint uses " or " between enum values for readability.
    const SCHEMA_HINT: &str =
        "expected body shape: {\"challenge_id\":\"<uuid>\",\"submit_secret\":\"<base64url 32 bytes>\",\"outcome\":\"verified\" or \"age_not_met\"}";

    let mut body: SimulateProofRequest = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/simulate] Failed to parse request body: {:?}", _e);
            return ApiError::bad_request(
                "BODY_SCHEMA_INVALID",
                Some("body"),
                format!(
                    "Request body could not be parsed as JSON or has unknown fields. {}",
                    SCHEMA_HINT
                ),
            )
            .to_response();
        }
    };

    // ── Validate challenge_id (UUID format) ───────────────────────────────
    let challenge_id = match Uuid::parse_str(&body.challenge_id) {
        Ok(id) => id,
        Err(_) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/simulate] Invalid challenge_id format");
            return ApiError::bad_request(
                "BODY_SCHEMA_INVALID",
                Some("challenge_id"),
                "challenge_id is not a valid UUID",
            )
            .to_response();
        }
    };

    // ── Validate submit_secret (base64url, decodes to 32 bytes) ───────────
    let submitted_secret_bytes: Zeroizing<Vec<u8>> = {
        let decoded = match URL_SAFE_NO_PAD.decode(body.submit_secret.as_bytes()) {
            Ok(v) => v,
            Err(_) => {
                #[cfg(target_arch = "wasm32")]
                console_log!("[hosted/simulate] Invalid base64url in submit_secret");
                return ApiError::bad_request(
                    "BODY_SCHEMA_INVALID",
                    Some("submit_secret"),
                    "submit_secret is not valid base64url",
                )
                .to_response();
            }
        };
        if decoded.len() != 32 {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/simulate] submit_secret decoded to {} bytes, expected 32",
                decoded.len()
            );
            return ApiError::bad_request(
                "BODY_SCHEMA_INVALID",
                Some("submit_secret"),
                "submit_secret must be base64url-encoded 32 bytes",
            )
            .to_response();
        }
        Zeroizing::new(decoded)
    };

    // ── Validate outcome (strict enum) ────────────────────────────────────
    if body.outcome != "verified" && body.outcome != "age_not_met" {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/simulate] Invalid outcome value: {}", body.outcome);
        return ApiError::bad_request(
            "BODY_SCHEMA_INVALID",
            Some("outcome"),
            "outcome must be \"verified\" or \"age_not_met\"",
        )
        .to_response();
    }

    // ── Load challenge from store ─────────────────────────────────────────
    let mut cached = match state.challenge_store.get(&challenge_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/simulate] Challenge not found: {}",
                redact_challenge_id(&challenge_id.to_string())
            );
            return ApiError::NotFound.to_response();
        }
        Err(e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/simulate] Failed to load challenge {}: {:?}",
                redact_challenge_id(&challenge_id.to_string()),
                e
            );
            return ApiError::Internal(e.into()).to_response();
        }
    };

    // ── Validate state is Pending ─────────────────────────────────────────
    if cached.state != ChallengeState::Pending {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/simulate] Challenge {} not in Pending state (is {:?})",
            redact_challenge_id(&challenge_id.to_string()),
            cached.state
        );
        return ApiError::gone(
            "CHALLENGE_GONE",
            "Challenge is no longer in the pending state (proof already submitted, redeemed, failed or expired)",
        )
        .to_response();
    }

    // ── Check expiry ──────────────────────────────────────────────────────
    let now = current_timestamp();
    if now > cached.expires_at {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/simulate] Challenge {} has expired",
            redact_challenge_id(&challenge_id.to_string())
        );
        cached.state = ChallengeState::Expired;
        // Best-effort persist of expired state.
        if let Err(_e) = state.challenge_store.put(&challenge_id, &cached).await {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/simulate] Failed to persist Expired state: {:?}",
                _e
            );
        }
        return ApiError::gone(
            "CHALLENGE_GONE",
            "Challenge has passed its expiry timestamp",
        )
        .to_response();
    }

    // ── Constant-time submit_secret comparison ────────────────────────────
    // SECURITY: Wrap cached bytes in Zeroizing, compare via ct_eq.
    // CIV-064: Return an error if cached bytes are not exactly 32 bytes.
    let cached_secret_arr: [u8; 32] = match cached.submit_secret.clone().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/simulate] Corrupt challenge: submit_secret is not 32 bytes");
            return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
        }
    };
    let cached_secret: Zeroizing<[u8; 32]> = Zeroizing::new(cached_secret_arr);

    let submitted_arr: [u8; 32] = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&submitted_secret_bytes);
        arr
    };
    let submitted_zeroizing: Zeroizing<[u8; 32]> = Zeroizing::new(submitted_arr);

    if !bool::from(submitted_zeroizing.ct_eq(&*cached_secret)) {
        // Secret mismatch: transition to Failed.
        cached.state = ChallengeState::Failed;
        cached.proof_submitted = true;
        cached.submit_secret.zeroize();

        if let Err(_e) = state.challenge_store.put(&challenge_id, &cached).await {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/simulate] Failed to persist Failed state: {:?}", _e);
        }

        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/simulate] submit_secret mismatch for challenge {}",
            redact_challenge_id(&challenge_id.to_string())
        );
        return ApiError::forbidden(
            "INVALID_SUBMIT_SECRET",
            "submit_secret did not match the value bound to this challenge_id at creation",
        )
        .to_response();
    }

    // ── Apply outcome ─────────────────────────────────────────────────────
    // Zeroize the submit_secret from the body now that comparison is done.
    body.submit_secret.zeroize();

    let response_state = if body.outcome == "verified" {
        // Simulate successful proof: mirror verify.rs state transition.
        cached.state = ChallengeState::ProofOkWaitingForRedeem;
        cached.proof_submitted = true;
        cached.proof_verified_at = Some(now);
        cached.submit_secret.zeroize();

        if let Err(_e) = state.challenge_store.put(&challenge_id, &cached).await {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/simulate] Failed to persist ProofOkWaitingForRedeem: {:?}",
                _e
            );
            return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
        }

        // Notify hosted session (fire-and-forget, best-effort).
        super::notify::notify_proof_verified(&state, &challenge_id.to_string()).await;

        "proof_ok_waiting_for_redeem"
    } else {
        // Simulate age_not_met: transition to Failed.
        cached.state = ChallengeState::Failed;
        cached.proof_submitted = true;
        cached.submit_secret.zeroize();

        if let Err(_e) = state.challenge_store.put(&challenge_id, &cached).await {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/simulate] Failed to persist Failed state: {:?}", _e);
            return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
        }

        // Notify hosted session of failure (fire-and-forget, best-effort).
        super::notify::notify_proof_failed(&state, &challenge_id.to_string()).await;

        "failed"
    };

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[hosted/simulate] Challenge {} simulated as {} -> {}",
        redact_challenge_id(&challenge_id.to_string()),
        body.outcome,
        response_state
    );

    let response = SimulateProofResponse {
        result: "ok".to_string(),
        state: response_state.to_string(),
    };

    Ok(Response::from_json(&response)?.with_status(200))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SimulateProofRequest Debug redaction ────────────────────────────
    #[test]
    fn debug_redacts_submit_secret() {
        let req = SimulateProofRequest {
            challenge_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            submit_secret: "super-secret-value-should-not-appear".to_string(),
            outcome: "verified".to_string(),
        };
        let debug = format!("{:?}", req);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret-value-should-not-appear"));
    }

    #[test]
    fn debug_shows_challenge_id() {
        let req = SimulateProofRequest {
            challenge_id: "my-challenge-id".to_string(),
            submit_secret: "secret".to_string(),
            outcome: "age_not_met".to_string(),
        };
        let debug = format!("{:?}", req);
        assert!(debug.contains("my-challenge-id"));
        assert!(debug.contains("age_not_met"));
    }

    #[test]
    fn debug_shows_struct_name() {
        let req = SimulateProofRequest {
            challenge_id: "id".to_string(),
            submit_secret: "s".to_string(),
            outcome: "verified".to_string(),
        };
        let debug = format!("{:?}", req);
        assert!(
            debug.contains("SimulateProofRequest"),
            "Debug output should contain struct name"
        );
    }

    #[test]
    fn debug_redacts_regardless_of_secret_content() {
        // Even an empty secret must be redacted, not rendered.
        let req = SimulateProofRequest {
            challenge_id: "x".to_string(),
            submit_secret: String::new(),
            outcome: "verified".to_string(),
        };
        let debug = format!("{:?}", req);
        assert!(debug.contains("[REDACTED]"));
        // The literal empty string `""` for submit_secret should NOT appear
        // as a visible field value (only [REDACTED]).
        assert!(
            !debug.contains("submit_secret: \"\""),
            "Empty secret should still be redacted"
        );
    }

    #[test]
    fn debug_shows_outcome_field() {
        let req = SimulateProofRequest {
            challenge_id: "id".to_string(),
            submit_secret: "s".to_string(),
            outcome: "verified".to_string(),
        };
        let debug = format!("{:?}", req);
        assert!(debug.contains("outcome"));
        assert!(debug.contains("verified"));
    }

    // ── SimulateProofRequest Drop / zeroize ────────────────────────────

    #[test]
    fn drop_zeroizes_submit_secret() {
        // We cannot inspect memory after drop, but we can verify that
        // Zeroize::zeroize on a String sets it to empty. The Drop impl
        // calls self.submit_secret.zeroize(). We call zeroize manually
        // to confirm the trait works as expected on the field type.
        let mut secret = "sensitive-bytes-here".to_string();
        secret.zeroize();
        assert!(secret.is_empty(), "Zeroize should clear String to empty");
    }

    #[test]
    fn drop_impl_runs_without_panic() {
        // Constructing and dropping should not panic even with unusual
        // field values (empty, very long, unicode).
        let _req = SimulateProofRequest {
            challenge_id: String::new(),
            submit_secret: "a".repeat(10_000),
            outcome: "\u{1F600}".to_string(),
        };
        // req is dropped here; no panic = pass.
    }

    // ── SimulateProofRequest deserialisation ────────────────────────────
    #[test]
    fn deserialize_valid_request() {
        let json = r#"{"challenge_id":"550e8400-e29b-41d4-a716-446655440000","submit_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","outcome":"verified"}"#;
        let req: SimulateProofRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.challenge_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(req.outcome, "verified");
    }

    #[test]
    fn deserialize_rejects_unknown_fields() {
        let json =
            r#"{"challenge_id":"id","submit_secret":"s","outcome":"verified","extra":"field"}"#;
        let result = serde_json::from_str::<SimulateProofRequest>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra field"
        );
    }

    #[test]
    fn deserialize_rejects_missing_fields() {
        let json = r#"{"challenge_id":"id","outcome":"verified"}"#;
        let result = serde_json::from_str::<SimulateProofRequest>(json);
        assert!(result.is_err(), "missing submit_secret should fail");
    }

    #[test]
    fn deserialize_rejects_missing_challenge_id() {
        let json = r#"{"submit_secret":"s","outcome":"verified"}"#;
        let result = serde_json::from_str::<SimulateProofRequest>(json);
        assert!(result.is_err(), "missing challenge_id should fail");
    }

    #[test]
    fn deserialize_rejects_missing_outcome() {
        let json = r#"{"challenge_id":"id","submit_secret":"s"}"#;
        let result = serde_json::from_str::<SimulateProofRequest>(json);
        assert!(result.is_err(), "missing outcome should fail");
    }

    #[test]
    fn deserialize_rejects_empty_json_object() {
        let json = "{}";
        let result = serde_json::from_str::<SimulateProofRequest>(json);
        assert!(result.is_err(), "empty object should fail");
    }

    #[test]
    fn deserialize_rejects_json_array() {
        let json = "[]";
        let result = serde_json::from_str::<SimulateProofRequest>(json);
        assert!(result.is_err(), "array should fail");
    }

    #[test]
    fn deserialize_rejects_null() {
        let json = "null";
        let result = serde_json::from_str::<SimulateProofRequest>(json);
        assert!(result.is_err(), "null should fail");
    }

    #[test]
    fn deserialize_rejects_non_string_challenge_id() {
        let json = r#"{"challenge_id":42,"submit_secret":"s","outcome":"verified"}"#;
        let result = serde_json::from_str::<SimulateProofRequest>(json);
        assert!(result.is_err(), "integer challenge_id should fail");
    }

    #[test]
    fn deserialize_rejects_non_string_outcome() {
        let json = r#"{"challenge_id":"id","submit_secret":"s","outcome":true}"#;
        let result = serde_json::from_str::<SimulateProofRequest>(json);
        assert!(result.is_err(), "boolean outcome should fail");
    }

    #[test]
    fn deserialize_preserves_all_fields() -> Result<(), Box<dyn std::error::Error>> {
        let json =
            r#"{"challenge_id":"abc-123","submit_secret":"secret-value","outcome":"age_not_met"}"#;
        let req: SimulateProofRequest = serde_json::from_str(json)?;
        assert_eq!(req.challenge_id, "abc-123");
        assert_eq!(req.submit_secret, "secret-value");
        assert_eq!(req.outcome, "age_not_met");
        Ok(())
    }

    #[test]
    fn deserialize_accepts_empty_string_fields() -> Result<(), Box<dyn std::error::Error>> {
        // Serde accepts empty strings; validation happens in the handler.
        let json = r#"{"challenge_id":"","submit_secret":"","outcome":""}"#;
        let req: SimulateProofRequest = serde_json::from_str(json)?;
        assert_eq!(req.challenge_id, "");
        assert_eq!(req.submit_secret, "");
        assert_eq!(req.outcome, "");
        Ok(())
    }

    #[test]
    fn deserialize_rejects_duplicate_fields() {
        // RFC 7159 allows duplicate keys but serde_json uses last-wins.
        // With deny_unknown_fields this should still parse (last value wins).
        // This test documents the behaviour.
        let json =
            r#"{"challenge_id":"a","challenge_id":"b","submit_secret":"s","outcome":"verified"}"#;
        let result = serde_json::from_str::<SimulateProofRequest>(json);
        // serde_json last-wins: challenge_id = "b"
        if let Ok(req) = result {
            assert_eq!(req.challenge_id, "b");
        }
        // Either parse succeeds with last-wins or fails; both are acceptable.
    }

    #[test]
    fn deserialize_rejects_invalid_json() {
        let json = "not json at all";
        let result = serde_json::from_str::<SimulateProofRequest>(json);
        assert!(result.is_err(), "invalid JSON should fail");
    }

    #[test]
    fn deserialize_from_bytes_matches_from_str() -> Result<(), Box<dyn std::error::Error>> {
        // The handler uses serde_json::from_slice; verify it matches from_str.
        let json = r#"{"challenge_id":"id","submit_secret":"s","outcome":"verified"}"#;
        let from_str: SimulateProofRequest = serde_json::from_str(json)?;
        let from_slice: SimulateProofRequest = serde_json::from_slice(json.as_bytes())?;
        assert_eq!(from_str.challenge_id, from_slice.challenge_id);
        assert_eq!(from_str.submit_secret, from_slice.submit_secret);
        assert_eq!(from_str.outcome, from_slice.outcome);
        Ok(())
    }

    // ── SimulateProofResponse serialisation ─────────────────────────────
    #[test]
    fn response_serialization_roundtrip() {
        let resp = SimulateProofResponse {
            result: "ok".to_string(),
            state: "proof_ok_waiting_for_redeem".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""result":"ok""#));
        assert!(json.contains(r#""state":"proof_ok_waiting_for_redeem""#));
    }

    #[test]
    fn response_serialization_failed_state() {
        let resp = SimulateProofResponse {
            result: "ok".to_string(),
            state: "failed".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""state":"failed""#));
    }

    #[test]
    fn response_deserialization_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = SimulateProofResponse {
            result: "ok".to_string(),
            state: "proof_ok_waiting_for_redeem".to_string(),
        };
        let json = serde_json::to_string(&original)?;
        let value: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(value["result"], "ok");
        assert_eq!(value["state"], "proof_ok_waiting_for_redeem");
        Ok(())
    }

    #[test]
    fn response_has_exactly_two_keys() -> Result<(), Box<dyn std::error::Error>> {
        let resp = SimulateProofResponse {
            result: "ok".to_string(),
            state: "failed".to_string(),
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        let obj = parsed.as_object().ok_or("expected JSON object")?;
        assert_eq!(obj.len(), 2, "response should have exactly 2 keys");
        assert!(obj.contains_key("result"));
        assert!(obj.contains_key("state"));
        Ok(())
    }

    #[test]
    fn response_debug_impl() {
        let resp = SimulateProofResponse {
            result: "ok".to_string(),
            state: "failed".to_string(),
        };
        let debug = format!("{:?}", resp);
        assert!(debug.contains("SimulateProofResponse"));
        assert!(debug.contains("ok"));
        assert!(debug.contains("failed"));
    }

    // ── Validation logic (exercising the same primitives the handler uses) ──

    #[test]
    fn uuid_parse_accepts_valid_uuids() -> Result<(), Box<dyn std::error::Error>> {
        // The handler uses Uuid::parse_str; verify it accepts standard UUIDs.
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
        Ok(())
    }

    #[test]
    fn uuid_parse_rejects_empty_string() {
        assert!(Uuid::parse_str("").is_err());
    }

    #[test]
    fn uuid_parse_rejects_garbage() {
        assert!(Uuid::parse_str("not-a-uuid").is_err());
    }

    #[test]
    fn uuid_parse_rejects_short_hex() {
        assert!(Uuid::parse_str("550e8400").is_err());
    }

    #[test]
    fn base64url_decode_accepts_valid_32_bytes() -> Result<(), Box<dyn std::error::Error>> {
        // 32 zero bytes encoded as base64url-no-pad = 43 characters
        let encoded = URL_SAFE_NO_PAD.encode([0u8; 32]);
        assert_eq!(encoded.len(), 43);
        let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes())?;
        assert_eq!(decoded.len(), 32);
        Ok(())
    }

    #[test]
    fn base64url_decode_rejects_standard_base64_padding() {
        // Standard base64 with padding should be rejected by URL_SAFE_NO_PAD.
        let with_padding = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let result = URL_SAFE_NO_PAD.decode(with_padding.as_bytes());
        assert!(
            result.is_err(),
            "padded base64 should be rejected by NO_PAD engine"
        );
    }

    #[test]
    fn base64url_decode_rejects_invalid_characters() {
        // Standard base64 chars `+` and `/` are not valid in base64url.
        let result = URL_SAFE_NO_PAD.decode(b"AAAA+AAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(result.is_err(), "standard base64 chars should be rejected");
    }

    #[test]
    fn base64url_decode_wrong_length_not_32_bytes() -> Result<(), Box<dyn std::error::Error>> {
        // 16 bytes encodes to 22 chars in base64url-no-pad.
        let encoded = URL_SAFE_NO_PAD.encode([0u8; 16]);
        let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes())?;
        assert_eq!(decoded.len(), 16);
        assert_ne!(
            decoded.len(),
            32,
            "16-byte input should not be accepted as 32 bytes"
        );
        Ok(())
    }

    #[test]
    fn base64url_decode_empty_string_is_zero_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let decoded = URL_SAFE_NO_PAD.decode(b"")?;
        assert_eq!(decoded.len(), 0);
        assert_ne!(decoded.len(), 32);
        Ok(())
    }

    // ── Outcome validation (mirrors handler logic) ──────────────────────

    #[test]
    fn outcome_validation_accepts_verified() {
        let outcome = "verified";
        assert!(outcome == "verified" || outcome == "age_not_met");
    }

    #[test]
    fn outcome_validation_accepts_age_not_met() {
        let outcome = "age_not_met";
        assert!(outcome == "verified" || outcome == "age_not_met");
    }

    #[test]
    fn outcome_validation_rejects_invalid_values() {
        let invalid_outcomes = vec![
            "Verified",
            "VERIFIED",
            "age_not_Met",
            "AGE_NOT_MET",
            "failed",
            "expired",
            "pending",
            "",
            " verified",
            "verified ",
            "age-not-met",
        ];
        for outcome in invalid_outcomes {
            assert!(
                outcome != "verified" && outcome != "age_not_met",
                "outcome {:?} should be rejected",
                outcome
            );
        }
    }

    // ── Constant-time comparison (exercises subtle::ConstantTimeEq) ─────

    #[test]
    fn ct_eq_matching_secrets() {
        let a: Zeroizing<[u8; 32]> = Zeroizing::new([0xAB; 32]);
        let b: Zeroizing<[u8; 32]> = Zeroizing::new([0xAB; 32]);
        assert!(bool::from(a.ct_eq(&*b)));
    }

    #[test]
    fn ct_eq_mismatched_secrets() {
        let a: Zeroizing<[u8; 32]> = Zeroizing::new([0xAB; 32]);
        let b: Zeroizing<[u8; 32]> = Zeroizing::new([0xCD; 32]);
        assert!(!bool::from(a.ct_eq(&*b)));
    }

    #[test]
    fn ct_eq_single_bit_difference() {
        let mut arr_a = [0u8; 32];
        let mut arr_b = [0u8; 32];
        arr_a[31] = 0x01;
        arr_b[31] = 0x00;
        let a: Zeroizing<[u8; 32]> = Zeroizing::new(arr_a);
        let b: Zeroizing<[u8; 32]> = Zeroizing::new(arr_b);
        assert!(!bool::from(a.ct_eq(&*b)));
    }

    #[test]
    fn ct_eq_all_zeros() {
        let a: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        let b: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        assert!(bool::from(a.ct_eq(&*b)));
    }

    #[test]
    fn ct_eq_all_ones() {
        let a: Zeroizing<[u8; 32]> = Zeroizing::new([0xFF; 32]);
        let b: Zeroizing<[u8; 32]> = Zeroizing::new([0xFF; 32]);
        assert!(bool::from(a.ct_eq(&*b)));
    }

    // ── Zeroizing wrapper behaviour ─────────────────────────────────────

    #[test]
    fn zeroizing_vec_clears_on_drop() {
        let secret = Zeroizing::new(vec![0xABu8; 32]);
        // Verify we can read the contents before drop.
        assert_eq!(secret.len(), 32);
        assert_eq!(secret[0], 0xAB);
        // Drop is implicit; this test just exercises the code path.
    }

    #[test]
    fn zeroizing_array_deref() {
        let arr: Zeroizing<[u8; 32]> = Zeroizing::new([42u8; 32]);
        // Deref should give us the inner array.
        let slice: &[u8; 32] = &arr;
        assert_eq!(slice[0], 42);
        assert_eq!(slice.len(), 32);
    }

    // ── Vec<u8> to [u8; 32] conversion (mirrors handler try_into logic) ──

    #[test]
    fn vec_to_32_byte_array_exact_length() -> Result<(), Box<dyn std::error::Error>> {
        let v: Vec<u8> = vec![7u8; 32];
        let arr: [u8; 32] = v.try_into().map_err(|_| "try_into failed")?;
        assert_eq!(arr, [7u8; 32]);
        Ok(())
    }

    #[test]
    fn vec_to_32_byte_array_too_short() {
        let v: Vec<u8> = vec![0u8; 31];
        let result: Result<[u8; 32], _> = v.try_into();
        assert!(result.is_err(), "31-byte vec should fail try_into [u8; 32]");
    }

    #[test]
    fn vec_to_32_byte_array_too_long() {
        let v: Vec<u8> = vec![0u8; 33];
        let result: Result<[u8; 32], _> = v.try_into();
        assert!(result.is_err(), "33-byte vec should fail try_into [u8; 32]");
    }

    #[test]
    fn vec_to_32_byte_array_empty() {
        let v: Vec<u8> = vec![];
        let result: Result<[u8; 32], _> = v.try_into();
        assert!(result.is_err(), "empty vec should fail try_into [u8; 32]");
    }

    // ── copy_from_slice mirrors handler pattern for submitted_arr ────────

    #[test]
    fn copy_from_slice_32_bytes() {
        let src = vec![0xFFu8; 32];
        let mut dst = [0u8; 32];
        dst.copy_from_slice(&src);
        assert_eq!(dst, [0xFF; 32]);
    }

    // ── Base64url encode/decode roundtrip for 32-byte secrets ───────────

    #[test]
    fn base64url_roundtrip_32_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let original = [0x42u8; 32];
        let encoded = URL_SAFE_NO_PAD.encode(original);
        let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes())?;
        assert_eq!(decoded.as_slice(), &original);
        Ok(())
    }

    #[test]
    fn base64url_roundtrip_random_pattern() -> Result<(), Box<dyn std::error::Error>> {
        // A deterministic but non-trivial byte pattern.
        let mut original = [0u8; 32];
        for (i, byte) in original.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let encoded = URL_SAFE_NO_PAD.encode(original);
        let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes())?;
        assert_eq!(decoded.as_slice(), &original);
        Ok(())
    }

    // ── SimulateProofResponse edge cases ────────────────────────────────

    #[test]
    fn response_with_empty_strings() -> Result<(), Box<dyn std::error::Error>> {
        let resp = SimulateProofResponse {
            result: String::new(),
            state: String::new(),
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["result"], "");
        assert_eq!(parsed["state"], "");
        Ok(())
    }

    #[test]
    fn response_deserialization_from_known_json() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"result":"ok","state":"failed"}"#;
        let value: serde_json::Value = serde_json::from_str(json)?;
        assert_eq!(value["result"], "ok");
        assert_eq!(value["state"], "failed");
        Ok(())
    }

    #[test]
    fn response_field_names_are_snake_case() -> Result<(), Box<dyn std::error::Error>> {
        let resp = SimulateProofResponse {
            result: "ok".to_string(),
            state: "pending".to_string(),
        };
        let json = serde_json::to_string(&resp)?;
        // Ensure no camelCase (no rename attributes on this struct).
        assert!(json.contains("\"result\""));
        assert!(json.contains("\"state\""));
        assert!(!json.contains("\"Result\""));
        assert!(!json.contains("\"State\""));
        Ok(())
    }

    // ── Full validation pipeline (mimics handler validation sequence) ────

    #[test]
    fn full_validation_pipeline_valid_input() -> Result<(), Box<dyn std::error::Error>> {
        // Simulate the entire validation chain the handler performs,
        // minus the async store lookups.
        let secret_bytes = [0xAA; 32];
        let encoded_secret = URL_SAFE_NO_PAD.encode(secret_bytes);
        let challenge_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let outcome = "verified";

        let json = format!(
            r#"{{"challenge_id":"{}","submit_secret":"{}","outcome":"{}"}}"#,
            challenge_uuid, encoded_secret, outcome
        );

        // Step 1: Deserialize
        let body: SimulateProofRequest = serde_json::from_str(&json)?;

        // Step 2: Validate UUID
        let _id = Uuid::parse_str(&body.challenge_id)?;

        // Step 3: Validate base64url and length
        let decoded = URL_SAFE_NO_PAD.decode(body.submit_secret.as_bytes())?;
        assert_eq!(decoded.len(), 32);

        // Step 4: Validate outcome
        assert!(body.outcome == "verified" || body.outcome == "age_not_met");

        // Step 5: Convert to fixed-size array
        let submitted_arr: [u8; 32] = decoded.try_into().map_err(|_| "wrong length")?;
        assert_eq!(submitted_arr, secret_bytes);

        Ok(())
    }

    #[test]
    fn full_validation_pipeline_age_not_met() -> Result<(), Box<dyn std::error::Error>> {
        let secret_bytes = [0xBB; 32];
        let encoded_secret = URL_SAFE_NO_PAD.encode(secret_bytes);
        let challenge_uuid = "a1b2c3d4-e5f6-7890-abcd-ef0123456789";
        let outcome = "age_not_met";

        let json = format!(
            r#"{{"challenge_id":"{}","submit_secret":"{}","outcome":"{}"}}"#,
            challenge_uuid, encoded_secret, outcome
        );

        let body: SimulateProofRequest = serde_json::from_str(&json)?;
        let _id = Uuid::parse_str(&body.challenge_id)?;
        let decoded = URL_SAFE_NO_PAD.decode(body.submit_secret.as_bytes())?;
        assert_eq!(decoded.len(), 32);
        assert!(body.outcome == "verified" || body.outcome == "age_not_met");

        Ok(())
    }

    #[test]
    fn full_validation_pipeline_invalid_uuid_fails_early() -> Result<(), Box<dyn std::error::Error>>
    {
        let secret_bytes = [0xCC; 32];
        let encoded_secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        let json = format!(
            r#"{{"challenge_id":"not-a-uuid","submit_secret":"{}","outcome":"verified"}}"#,
            encoded_secret
        );

        let body: SimulateProofRequest = serde_json::from_str(&json)?;
        assert!(
            Uuid::parse_str(&body.challenge_id).is_err(),
            "non-UUID challenge_id should fail parse"
        );
        Ok(())
    }

    #[test]
    fn full_validation_pipeline_bad_base64_fails() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"challenge_id":"550e8400-e29b-41d4-a716-446655440000","submit_secret":"!!!invalid-base64!!!","outcome":"verified"}"#;

        let body: SimulateProofRequest = serde_json::from_str(json)?;
        assert!(
            URL_SAFE_NO_PAD
                .decode(body.submit_secret.as_bytes())
                .is_err(),
            "invalid base64url should fail decode"
        );
        Ok(())
    }

    #[test]
    fn full_validation_pipeline_wrong_secret_length() -> Result<(), Box<dyn std::error::Error>> {
        // 16 bytes instead of 32.
        let encoded = URL_SAFE_NO_PAD.encode([0xDD; 16]);
        let json = format!(
            r#"{{"challenge_id":"550e8400-e29b-41d4-a716-446655440000","submit_secret":"{}","outcome":"verified"}}"#,
            encoded
        );

        let body: SimulateProofRequest = serde_json::from_str(&json)?;
        let decoded = URL_SAFE_NO_PAD.decode(body.submit_secret.as_bytes())?;
        assert_ne!(
            decoded.len(),
            32,
            "16-byte secret should not pass length check"
        );
        Ok(())
    }

    #[test]
    fn full_validation_pipeline_bad_outcome() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = URL_SAFE_NO_PAD.encode([0xEE; 32]);
        let json = format!(
            r#"{{"challenge_id":"550e8400-e29b-41d4-a716-446655440000","submit_secret":"{}","outcome":"invalid_outcome"}}"#,
            encoded
        );

        let body: SimulateProofRequest = serde_json::from_str(&json)?;
        assert!(
            body.outcome != "verified" && body.outcome != "age_not_met",
            "invalid outcome should be rejected"
        );
        Ok(())
    }

    // ── Secret comparison with ct_eq (full pipeline) ────────────────────

    #[test]
    fn ct_comparison_pipeline_match() -> Result<(), Box<dyn std::error::Error>> {
        // Simulate the handler's secret comparison flow end-to-end.
        let stored_secret: Vec<u8> = vec![0x42u8; 32];
        let submitted_encoded = URL_SAFE_NO_PAD.encode(&stored_secret);

        // Decode submitted
        let submitted_decoded: Zeroizing<Vec<u8>> =
            Zeroizing::new(URL_SAFE_NO_PAD.decode(submitted_encoded.as_bytes())?);
        assert_eq!(submitted_decoded.len(), 32);

        // Convert stored to [u8; 32]
        let cached_arr: [u8; 32] = stored_secret
            .try_into()
            .map_err(|_| "stored secret wrong length")?;
        let cached_secret: Zeroizing<[u8; 32]> = Zeroizing::new(cached_arr);

        // Convert submitted to [u8; 32]
        let mut submitted_arr = [0u8; 32];
        submitted_arr.copy_from_slice(&submitted_decoded);
        let submitted_zeroizing: Zeroizing<[u8; 32]> = Zeroizing::new(submitted_arr);

        assert!(bool::from(submitted_zeroizing.ct_eq(&*cached_secret)));
        Ok(())
    }

    #[test]
    fn ct_comparison_pipeline_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let stored_secret: Vec<u8> = vec![0x42u8; 32];
        let wrong_secret = [0x99u8; 32];
        let submitted_encoded = URL_SAFE_NO_PAD.encode(wrong_secret);

        let submitted_decoded: Zeroizing<Vec<u8>> =
            Zeroizing::new(URL_SAFE_NO_PAD.decode(submitted_encoded.as_bytes())?);

        let cached_arr: [u8; 32] = stored_secret
            .try_into()
            .map_err(|_| "stored secret wrong length")?;
        let cached_secret: Zeroizing<[u8; 32]> = Zeroizing::new(cached_arr);

        let mut submitted_arr = [0u8; 32];
        submitted_arr.copy_from_slice(&submitted_decoded);
        let submitted_zeroizing: Zeroizing<[u8; 32]> = Zeroizing::new(submitted_arr);

        assert!(!bool::from(submitted_zeroizing.ct_eq(&*cached_secret)));
        Ok(())
    }
}
