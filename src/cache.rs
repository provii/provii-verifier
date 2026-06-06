// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! KV-backed cache models for challenge workflow state.
//!
//! [`CachedChallenge`] is the primary struct serialised to and deserialised from
//! the challenge KV namespace. Secret byte fields are zeroised on drop, and the
//! manual [`Debug`] impl redacts all cryptographic material.
#![forbid(unsafe_code)]

use crate::storage::origin_policy::ProofDirection;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroize;

/// Expected byte length for cryptographic fields in a cached challenge.
const CHALLENGE_FIELD_LEN: usize = 32;

/// Lifecycle state of a challenge as it moves through the verification flow.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeState {
    /// Challenge created and waiting for a proof submission.
    Pending,
    /// Proof verified successfully and awaiting PKCE redemption.
    ProofOkWaitingForRedeem,
    /// Proof verified and PKCE redemption completed.
    Verified,
    /// Proof verification failed or the challenge was rejected.
    Failed,
    /// Challenge exceeded its TTL without completing verification.
    Expired,
}

impl ChallengeState {
    /// Return the snake_case string representation used in API responses.
    pub fn as_str(&self) -> &'static str {
        match self {
            ChallengeState::Pending => "pending",
            ChallengeState::ProofOkWaitingForRedeem => "proof_ok_waiting_for_redeem",
            ChallengeState::Verified => "verified",
            ChallengeState::Failed => "failed",
            ChallengeState::Expired => "expired",
        }
    }
}

/// A challenge entry serialised into the KV challenge store.
///
/// Contains all state needed to track a single verification attempt from
/// creation through proof submission, PKCE redemption, and expiry. Secret
/// byte fields are zeroised on [`Drop`].
#[derive(Clone, Serialize, Deserialize)]
pub struct CachedChallenge {
    /// Unique identifier for this challenge (UUIDv4).
    pub id: Uuid,
    /// 12-digit numeric short code for accessibility (displayed as XXXX XXXX XXXX).
    pub short_code: String,
    /// 32-byte RP challenge derived from the origin and nonce.
    pub rp_challenge: Vec<u8>,
    /// Age cutoff expressed as days since epoch, signed to allow edge cases.
    pub cutoff_days: i32,
    /// Index of the verifying key used for this challenge.
    pub verifying_key_id: u32,
    /// Base64url encoded PKCE code challenge supplied by the client.
    pub code_challenge: String,
    /// Raw 32-byte PKCE code challenge used for constant-time comparisons.
    pub code_challenge_bytes: Vec<u8>,
    /// 32-byte anti-abuse secret embedded in the verification request.
    pub submit_secret: Vec<u8>,
    /// Origin that created this challenge (used for CORS and RP binding).
    pub origin: String,
    /// Unix timestamp (seconds) at which this challenge expires.
    pub expires_at: u64,
    /// Unix timestamp (seconds) at which this challenge was created.
    pub created_at: u64,
    /// Current lifecycle state of this challenge.
    pub state: ChallengeState,
    /// Whether a proof has been submitted against this challenge.
    pub proof_submitted: bool,
    /// Unix timestamp (seconds) when PKCE redemption completed, if any.
    pub verified_at: Option<u64>,
    /// Unix timestamp (seconds) when the ZK proof was verified, if any.
    pub proof_verified_at: Option<u64>,
    /// Issuer identifier captured during proof verification for billing.
    pub issuer_kid: Option<String>,
    /// Raw verifying key bytes associated with the issuer, when available.
    pub issuer_vk_bytes: Option<[u8; 32]>,
    /// Optional verifier client identifier for multi-tenant billing.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Tenant identifier from the origin policy, used as customer_id for billing.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Proof direction: OverAge (default) or UnderAge.
    ///
    /// Changed from `String` to `ProofDirection` enum for exhaustive
    /// match arms and compile-time validation. Serde serialises identically
    /// (`"over_age"` / `"under_age"`) so existing KV entries deserialise
    /// without migration.
    #[serde(default)]
    pub proof_direction: ProofDirection,
}

impl CachedChallenge {
    /// CIV-132: Validate that security-critical byte fields have the expected length.
    ///
    /// Returns `Ok(())` if all fields are valid, or an error string describing the
    /// first field that fails validation. Call this after deserialising from KV to
    /// reject corrupted or tampered entries early.
    pub fn validate(&self) -> Result<(), String> {
        if self.rp_challenge.len() != CHALLENGE_FIELD_LEN {
            return Err(format!(
                "rp_challenge length {} != {}",
                self.rp_challenge.len(),
                CHALLENGE_FIELD_LEN
            ));
        }
        // submit_secret is intentionally zeroized (emptied) after proof
        // verification, so allow length 0 for non-Pending challenges.
        if !self.submit_secret.is_empty() && self.submit_secret.len() != CHALLENGE_FIELD_LEN {
            return Err(format!(
                "submit_secret length {} != {}",
                self.submit_secret.len(),
                CHALLENGE_FIELD_LEN
            ));
        }
        if self.code_challenge_bytes.len() != CHALLENGE_FIELD_LEN {
            return Err(format!(
                "code_challenge_bytes length {} != {}",
                self.code_challenge_bytes.len(),
                CHALLENGE_FIELD_LEN
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for CachedChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedChallenge")
            .field("id", &self.id)
            .field("short_code", &self.short_code)
            .field("rp_challenge", &"[REDACTED 32 bytes]")
            .field("cutoff_days", &self.cutoff_days)
            .field("verifying_key_id", &self.verifying_key_id)
            .field("code_challenge", &self.code_challenge)
            .field("code_challenge_bytes", &"[REDACTED]")
            .field("submit_secret", &"[REDACTED 32 bytes]")
            .field("origin", &self.origin)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .field("state", &self.state)
            .field("proof_submitted", &self.proof_submitted)
            .field("verified_at", &self.verified_at)
            .field("proof_verified_at", &self.proof_verified_at)
            .field("issuer_kid", &self.issuer_kid)
            .field(
                "issuer_vk_bytes",
                &self.issuer_vk_bytes.as_ref().map(|_| "[REDACTED]"),
            )
            .field("client_id", &self.client_id)
            .field("tenant_id", &self.tenant_id)
            .field("proof_direction", &self.proof_direction)
            .finish()
    }
}

impl Drop for CachedChallenge {
    fn drop(&mut self) {
        self.rp_challenge.zeroize();
        self.code_challenge.zeroize();
        self.code_challenge_bytes.zeroize();
        self.submit_secret.zeroize();
        if let Some(bytes) = self.issuer_vk_bytes.as_mut() {
            bytes.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    ChallengeState TESTS                                   */
    /* ========================================================================== */

    #[test]
    fn test_challenge_state_as_str() {
        assert_eq!(ChallengeState::Pending.as_str(), "pending");
        assert_eq!(
            ChallengeState::ProofOkWaitingForRedeem.as_str(),
            "proof_ok_waiting_for_redeem"
        );
        assert_eq!(ChallengeState::Verified.as_str(), "verified");
        assert_eq!(ChallengeState::Failed.as_str(), "failed");
        assert_eq!(ChallengeState::Expired.as_str(), "expired");
    }

    #[test]
    fn test_challenge_state_clone() {
        let state = ChallengeState::Pending;
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }

    #[test]
    fn test_challenge_state_equality() {
        assert_eq!(ChallengeState::Pending, ChallengeState::Pending);
        assert_ne!(ChallengeState::Pending, ChallengeState::Verified);
    }

    #[test]
    fn test_challenge_state_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&ChallengeState::Verified)?;
        assert!(json.contains("Verified"));
        Ok(())
    }

    #[test]
    fn test_challenge_state_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let json = "\"Pending\"";
        let state: ChallengeState = serde_json::from_str(json)?;
        assert_eq!(state, ChallengeState::Pending);
        Ok(())
    }

    #[test]
    fn test_challenge_state_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let states = vec![
            ChallengeState::Pending,
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];

        for state in states {
            let json = serde_json::to_string(&state)?;
            let decoded: ChallengeState = serde_json::from_str(&json)?;
            assert_eq!(state, decoded);
        }
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge TESTS                                  */
    /* ========================================================================== */

    fn create_test_challenge() -> CachedChallenge {
        CachedChallenge {
            id: Uuid::new_v4(),
            short_code: "123456789012".to_string(),
            rp_challenge: vec![1, 2, 3, 4],
            cutoff_days: 6570,
            verifying_key_id: 1,
            code_challenge: "test_challenge".to_string(),
            code_challenge_bytes: vec![5, 6, 7, 8],
            submit_secret: vec![9, 10, 11, 12],
            origin: "https://example.com".to_string(),
            expires_at: 1234567890,
            created_at: 1234567800,
            state: ChallengeState::Pending,
            proof_submitted: false,
            verified_at: None,
            proof_verified_at: None,
            issuer_kid: None,
            issuer_vk_bytes: None,
            client_id: None,
            tenant_id: None,
            proof_direction: ProofDirection::OverAge,
        }
    }

    #[test]
    fn test_cached_challenge_creation() {
        let challenge = create_test_challenge();
        assert_eq!(challenge.cutoff_days, 6570);
        assert_eq!(challenge.origin, "https://example.com");
        assert_eq!(challenge.state, ChallengeState::Pending);
    }

    #[test]
    fn test_cached_challenge_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let challenge = create_test_challenge();
        let json = serde_json::to_string(&challenge)?;
        assert!(json.contains("example.com"));
        assert!(json.contains("6570"));
        Ok(())
    }

    #[test]
    fn test_cached_challenge_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let challenge = create_test_challenge();
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(challenge.origin, decoded.origin);
        assert_eq!(challenge.cutoff_days, decoded.cutoff_days);
        Ok(())
    }

    #[test]
    fn test_cached_challenge_clone() {
        let challenge = create_test_challenge();
        let cloned = challenge.clone();
        assert_eq!(challenge.id, cloned.id);
        assert_eq!(challenge.origin, cloned.origin);
    }

    #[test]
    fn test_cached_challenge_with_verified_state() {
        let mut challenge = create_test_challenge();
        challenge.state = ChallengeState::Verified;
        challenge.verified_at = Some(1234567900);
        assert_eq!(challenge.state, ChallengeState::Verified);
        assert_eq!(challenge.verified_at, Some(1234567900));
    }

    #[test]
    fn test_cached_challenge_with_issuer_info() {
        let mut challenge = create_test_challenge();
        challenge.issuer_kid = Some("issuer-123".to_string());
        challenge.issuer_vk_bytes = Some([42u8; 32]);
        assert_eq!(challenge.issuer_kid, Some("issuer-123".to_string()));
        assert!(challenge.issuer_vk_bytes.is_some());
    }

    #[test]
    fn test_cached_challenge_with_client_id() {
        let mut challenge = create_test_challenge();
        challenge.client_id = Some("client-456".to_string());
        assert_eq!(challenge.client_id, Some("client-456".to_string()));
    }

    #[test]
    fn test_cached_challenge_proof_submitted() {
        let mut challenge = create_test_challenge();
        challenge.proof_submitted = true;
        challenge.proof_verified_at = Some(1234567850);
        assert!(challenge.proof_submitted);
        assert_eq!(challenge.proof_verified_at, Some(1234567850));
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: CachedChallenge with any cutoff_days roundtrips through serde
        #[test]
        fn prop_challenge_cutoff_days(cutoff in any::<i32>()) {
            let mut challenge = create_test_challenge();
            challenge.cutoff_days = cutoff;
            let json = serde_json::to_string(&challenge)
                .map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let decoded: CachedChallenge = serde_json::from_str(&json)
                .map_err(|e| TestCaseError::fail(format!("{e}")))?;
            prop_assert_eq!(decoded.cutoff_days, cutoff);
        }

        /// Property: CachedChallenge with any origin roundtrips through serde
        #[test]
        fn prop_challenge_origin(origin in "https://[a-z]{0,20}\\.com") {
            let mut challenge = create_test_challenge();
            challenge.origin = origin.clone();
            let json = serde_json::to_string(&challenge)
                .map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let decoded: CachedChallenge = serde_json::from_str(&json)
                .map_err(|e| TestCaseError::fail(format!("{e}")))?;
            prop_assert_eq!(decoded.origin.clone(), origin);
        }

        /// Property: CachedChallenge timestamps roundtrip through serde
        #[test]
        fn prop_challenge_timestamps(created in any::<u64>(), expires in any::<u64>()) {
            let mut challenge = create_test_challenge();
            challenge.created_at = created;
            challenge.expires_at = expires;
            let json = serde_json::to_string(&challenge)
                .map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let decoded: CachedChallenge = serde_json::from_str(&json)
                .map_err(|e| TestCaseError::fail(format!("{e}")))?;
            prop_assert_eq!(decoded.created_at, created);
            prop_assert_eq!(decoded.expires_at, expires);
        }

        /// Property: CachedChallenge clone preserves all fields
        #[test]
        fn prop_challenge_clone_preserves(
            cutoff in any::<i32>(),
            vk_id in any::<u32>()
        ) {
            let mut challenge = create_test_challenge();
            challenge.cutoff_days = cutoff;
            challenge.verifying_key_id = vk_id;

            let cloned = challenge.clone();
            prop_assert_eq!(challenge.cutoff_days, cloned.cutoff_days);
            prop_assert_eq!(challenge.verifying_key_id, cloned.verifying_key_id);
            prop_assert_eq!(challenge.id, cloned.id);
            prop_assert_eq!(challenge.origin.clone(), cloned.origin.clone());
            prop_assert_eq!(challenge.state.clone(), cloned.state.clone());
        }
    }

    /* ========================================================================== */
    /*                    CIV-132: validate() TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_validate_correct_lengths() {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![0u8; 32];
        challenge.code_challenge_bytes = vec![0u8; 32];
        assert!(challenge.validate().is_ok());
    }

    #[test]
    fn test_validate_rp_challenge_too_short() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 16];
        challenge.submit_secret = vec![0u8; 32];
        challenge.code_challenge_bytes = vec![0u8; 32];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(err.contains("rp_challenge"));
        Ok(())
    }

    #[test]
    fn test_validate_submit_secret_too_long() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![0u8; 64];
        challenge.code_challenge_bytes = vec![0u8; 32];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(err.contains("submit_secret"));
        Ok(())
    }

    #[test]
    fn test_validate_code_challenge_bytes_empty() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![0u8; 32];
        challenge.code_challenge_bytes = vec![];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(err.contains("code_challenge_bytes"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    ProofDirection default TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_default_proof_direction() {
        assert_eq!(ProofDirection::default(), ProofDirection::OverAge);
    }

    /* ========================================================================== */
    /*                    ChallengeState Debug TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_challenge_state_debug_format() {
        let cases = [
            (ChallengeState::Pending, "Pending"),
            (
                ChallengeState::ProofOkWaitingForRedeem,
                "ProofOkWaitingForRedeem",
            ),
            (ChallengeState::Verified, "Verified"),
            (ChallengeState::Failed, "Failed"),
            (ChallengeState::Expired, "Expired"),
        ];
        for (state, expected) in cases {
            let debug = format!("{:?}", state);
            assert!(
                debug.contains(expected),
                "Expected {:?} to contain {}",
                debug,
                expected
            );
        }
    }

    /* ========================================================================== */
    /*                    ChallengeState serde edge cases                        */
    /* ========================================================================== */

    #[test]
    fn test_challenge_state_deserialize_invalid_variant() {
        let json = "\"Unknown\"";
        let result: Result<ChallengeState, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_state_deserialize_empty_string() {
        let json = "\"\"";
        let result: Result<ChallengeState, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_state_deserialize_lowercase_fails() {
        // serde expects exact case for externally tagged enums
        let json = "\"pending\"";
        let result: Result<ChallengeState, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    CachedChallenge Debug redaction TESTS                  */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_debug_redacts_rp_challenge() {
        let challenge = create_test_challenge();
        let debug = format!("{:?}", challenge);
        assert!(debug.contains("[REDACTED 32 bytes]"));
        // Secret bytes should NOT appear in debug output
        assert!(!debug.contains("[1, 2, 3, 4]"));
    }

    #[test]
    fn test_cached_challenge_debug_redacts_code_challenge_bytes() {
        let challenge = create_test_challenge();
        let debug = format!("{:?}", challenge);
        assert!(!debug.contains("[5, 6, 7, 8]"));
    }

    #[test]
    fn test_cached_challenge_debug_redacts_submit_secret() {
        let challenge = create_test_challenge();
        let debug = format!("{:?}", challenge);
        assert!(!debug.contains("[9, 10, 11, 12]"));
    }

    #[test]
    fn test_cached_challenge_debug_shows_public_fields() {
        let challenge = create_test_challenge();
        let debug = format!("{:?}", challenge);
        assert!(debug.contains("CachedChallenge"));
        assert!(debug.contains("example.com"));
        assert!(debug.contains("6570"));
        assert!(debug.contains("Pending"));
        assert!(debug.contains("123456789012"));
    }

    #[test]
    fn test_cached_challenge_debug_redacts_issuer_vk_bytes() {
        let mut challenge = create_test_challenge();
        challenge.issuer_vk_bytes = Some([99u8; 32]);
        let debug = format!("{:?}", challenge);
        // Should show "[REDACTED]" for issuer_vk_bytes, not the raw bytes
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_cached_challenge_debug_none_issuer_vk_bytes() {
        let challenge = create_test_challenge();
        let debug = format!("{:?}", challenge);
        assert!(debug.contains("issuer_vk_bytes: None"));
    }

    /* ========================================================================== */
    /*                    CIV-132: validate() additional TESTS                   */
    /* ========================================================================== */

    #[test]
    fn test_validate_empty_submit_secret_allowed() {
        // Empty submit_secret is allowed for non-Pending challenges
        // (it is intentionally zeroized after proof verification)
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![]; // zeroized
        challenge.code_challenge_bytes = vec![0u8; 32];
        assert!(challenge.validate().is_ok());
    }

    #[test]
    fn test_validate_rp_challenge_too_long() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 64];
        challenge.submit_secret = vec![0u8; 32];
        challenge.code_challenge_bytes = vec![0u8; 32];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(err.contains("rp_challenge"));
        assert!(err.contains("64"));
        Ok(())
    }

    #[test]
    fn test_validate_rp_challenge_empty() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![];
        challenge.submit_secret = vec![0u8; 32];
        challenge.code_challenge_bytes = vec![0u8; 32];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(err.contains("rp_challenge"));
        Ok(())
    }

    #[test]
    fn test_validate_code_challenge_bytes_wrong_length() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![0u8; 32];
        challenge.code_challenge_bytes = vec![0u8; 16];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(err.contains("code_challenge_bytes"));
        assert!(err.contains("16"));
        Ok(())
    }

    #[test]
    fn test_validate_submit_secret_one_byte() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![0u8; 1];
        challenge.code_challenge_bytes = vec![0u8; 32];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(err.contains("submit_secret"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge serde defaults TESTS                   */
    /* ========================================================================== */

    #[test]
    fn test_proof_direction_defaults_on_missing() -> Result<(), Box<dyn std::error::Error>> {
        // Serialise then remove proof_direction to simulate old KV entries
        let challenge = create_test_challenge();
        let mut json_val: serde_json::Value = serde_json::to_value(&challenge)?;
        if let serde_json::Value::Object(ref mut map) = json_val {
            map.remove("proof_direction");
        }
        let decoded: CachedChallenge = serde_json::from_value(json_val)?;
        assert_eq!(decoded.proof_direction, ProofDirection::OverAge);
        Ok(())
    }

    #[test]
    fn test_client_id_defaults_on_missing() -> Result<(), Box<dyn std::error::Error>> {
        let challenge = create_test_challenge();
        let mut json_val: serde_json::Value = serde_json::to_value(&challenge)?;
        if let serde_json::Value::Object(ref mut map) = json_val {
            map.remove("client_id");
        }
        let decoded: CachedChallenge = serde_json::from_value(json_val)?;
        assert_eq!(decoded.client_id, None);
        Ok(())
    }

    #[test]
    fn test_tenant_id_defaults_on_missing() -> Result<(), Box<dyn std::error::Error>> {
        let challenge = create_test_challenge();
        let mut json_val: serde_json::Value = serde_json::to_value(&challenge)?;
        if let serde_json::Value::Object(ref mut map) = json_val {
            map.remove("tenant_id");
        }
        let decoded: CachedChallenge = serde_json::from_value(json_val)?;
        assert_eq!(decoded.tenant_id, None);
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge with under_age proof_direction         */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_under_age_direction() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.proof_direction = ProofDirection::UnderAge;
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.proof_direction, ProofDirection::UnderAge);
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge all states round-trip                  */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_all_states_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let states = [
            ChallengeState::Pending,
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];
        for state in states {
            let mut challenge = create_test_challenge();
            challenge.state = state.clone();
            let json = serde_json::to_string(&challenge)?;
            let decoded: CachedChallenge = serde_json::from_str(&json)?;
            assert_eq!(decoded.state, state);
        }
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge cutoff_days edge cases                 */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_negative_cutoff_days() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.cutoff_days = -100;
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.cutoff_days, -100);
        Ok(())
    }

    #[test]
    fn test_cached_challenge_min_cutoff_days() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.cutoff_days = i32::MIN;
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.cutoff_days, i32::MIN);
        Ok(())
    }

    #[test]
    fn test_cached_challenge_max_cutoff_days() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.cutoff_days = i32::MAX;
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.cutoff_days, i32::MAX);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ChallengeState as_str exhaustive                       */
    /* ========================================================================== */

    #[test]
    fn test_challenge_state_as_str_no_uppercase() {
        // API responses use snake_case; verify no variant uses PascalCase
        let states = [
            ChallengeState::Pending,
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];
        for state in states {
            let s = state.as_str();
            assert_eq!(
                s,
                s.to_ascii_lowercase(),
                "as_str() should be lowercase snake_case: got {}",
                s
            );
        }
    }

    /* ========================================================================== */
    /*                    EDGE CASE TESTS                                        */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_with_very_large_byte_arrays() -> Result<(), Box<dyn std::error::Error>>
    {
        // Test serialisation/deserialisation with large Vec<u8> fields
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0xFF; 65536]; // 64KB
        challenge.code_challenge_bytes = vec![0xAA; 65536];
        challenge.submit_secret = vec![0x55; 65536];

        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;

        assert_eq!(decoded.rp_challenge.len(), 65536);
        assert_eq!(decoded.code_challenge_bytes.len(), 65536);
        assert_eq!(decoded.submit_secret.len(), 65536);
        Ok(())
    }

    #[test]
    fn test_cached_challenge_timestamp_at_max_u64() -> Result<(), Box<dyn std::error::Error>> {
        // Test with timestamp at maximum u64 value
        let mut challenge = create_test_challenge();
        challenge.created_at = u64::MAX;
        challenge.expires_at = u64::MAX;
        challenge.verified_at = Some(u64::MAX);
        challenge.proof_verified_at = Some(u64::MAX);

        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;

        assert_eq!(decoded.created_at, u64::MAX);
        assert_eq!(decoded.expires_at, u64::MAX);
        assert_eq!(decoded.verified_at, Some(u64::MAX));
        assert_eq!(decoded.proof_verified_at, Some(u64::MAX));
        Ok(())
    }

    #[test]
    fn test_cached_challenge_timestamp_at_zero() -> Result<(), Box<dyn std::error::Error>> {
        // Test with timestamp at zero (epoch)
        let mut challenge = create_test_challenge();
        challenge.created_at = 0;
        challenge.expires_at = 0;
        challenge.verified_at = Some(0);
        challenge.proof_verified_at = Some(0);

        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;

        assert_eq!(decoded.created_at, 0);
        assert_eq!(decoded.expires_at, 0);
        assert_eq!(decoded.verified_at, Some(0));
        assert_eq!(decoded.proof_verified_at, Some(0));
        Ok(())
    }

    #[test]
    fn test_cached_challenge_deserialize_with_invalid_uuid() {
        // Test deserialisation with invalid UUID string
        let invalid_json = r#"{
            "id": "not-a-valid-uuid",
            "rp_challenge": [1,2,3],
            "cutoff_days": 6570,
            "verifying_key_id": 1,
            "code_challenge": "test",
            "code_challenge_bytes": [4,5,6],
            "submit_secret": [7,8,9],
            "origin": "https://example.com",
            "expires_at": 1234567890,
            "created_at": 1234567800,
            "state": "Pending",
            "proof_submitted": false,
            "verified_at": null,
            "proof_verified_at": null,
            "issuer_kid": null,
            "issuer_vk_bytes": null,
            "client_id": null
        }"#;

        let result: Result<CachedChallenge, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_cached_challenge_deserialize_with_missing_fields() {
        // Test deserialisation with missing required fields
        let incomplete_json = r#"{
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "cutoff_days": 6570
        }"#;

        let result: Result<CachedChallenge, _> = serde_json::from_str(incomplete_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_cached_challenge_deserialize_with_extra_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Test that extra fields are ignored during deserialisation
        let challenge = create_test_challenge();
        let mut json: serde_json::Value = serde_json::to_value(&challenge)?;

        // Add extra fields that shouldn't break deserialisation
        if let serde_json::Value::Object(ref mut map) = json {
            map.insert(
                "extra_field_1".to_string(),
                serde_json::Value::String("ignored".to_string()),
            );
            map.insert(
                "extra_field_2".to_string(),
                serde_json::Value::Number(serde_json::Number::from(999)),
            );
            map.insert("unknown_bool".to_string(), serde_json::Value::Bool(true));
        }

        let decoded: CachedChallenge = serde_json::from_value(json)?;
        assert_eq!(decoded.origin, challenge.origin);
        assert_eq!(decoded.cutoff_days, challenge.cutoff_days);
        Ok(())
    }

    #[test]
    fn test_cached_challenge_deserialize_with_malformed_json() {
        // Test various malformed JSON scenarios
        let malformed_cases = vec![
            r#"{"id": "invalid", "cutoff_days": "not a number"}"#, // Wrong type
            r#"{"id": 12345, "origin": []}"#,                      // Wrong types
            r#"{"rp_challenge": "not an array"}"#,                 // String instead of Vec<u8>
            r#"{"state": "InvalidState"}"#,                        // Invalid enum variant
        ];

        for malformed in malformed_cases {
            let result: Result<CachedChallenge, _> = serde_json::from_str(malformed);
            assert!(result.is_err(), "Should fail to parse: {}", malformed);
        }
    }

    /* ========================================================================== */
    /*                    CHALLENGE_FIELD_LEN constant                           */
    /* ========================================================================== */

    #[test]
    fn test_challenge_field_len_is_32() {
        assert_eq!(CHALLENGE_FIELD_LEN, 32);
    }

    /* ========================================================================== */
    /*                    ChallengeState: as_str returns distinct values         */
    /* ========================================================================== */

    #[test]
    fn test_challenge_state_as_str_all_unique() {
        let states = [
            ChallengeState::Pending,
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];
        let strs: Vec<&str> = states.iter().map(|s| s.as_str()).collect();
        // Each pair should be distinct
        for i in 0..strs.len() {
            for j in (i.checked_add(1).unwrap_or(strs.len()))..strs.len() {
                assert_ne!(
                    strs[i], strs[j],
                    "as_str() collision between index {} and {}",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_challenge_state_as_str_contains_no_whitespace() {
        let states = [
            ChallengeState::Pending,
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];
        for state in states {
            let s = state.as_str();
            assert!(
                !s.contains(' '),
                "as_str() should not contain spaces: {}",
                s
            );
            assert!(!s.contains('\t'), "as_str() should not contain tabs: {}", s);
        }
    }

    /* ========================================================================== */
    /*                    ChallengeState: serialisation format                   */
    /* ========================================================================== */

    #[test]
    fn test_challenge_state_serialize_all_variants() -> Result<(), Box<dyn std::error::Error>> {
        let expected_pairs = [
            (ChallengeState::Pending, "Pending"),
            (
                ChallengeState::ProofOkWaitingForRedeem,
                "ProofOkWaitingForRedeem",
            ),
            (ChallengeState::Verified, "Verified"),
            (ChallengeState::Failed, "Failed"),
            (ChallengeState::Expired, "Expired"),
        ];
        for (state, expected_str) in expected_pairs {
            let json = serde_json::to_string(&state)?;
            assert_eq!(json, format!("\"{}\"", expected_str));
        }
        Ok(())
    }

    #[test]
    fn test_challenge_state_deserialize_all_variants() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            ("\"Pending\"", ChallengeState::Pending),
            (
                "\"ProofOkWaitingForRedeem\"",
                ChallengeState::ProofOkWaitingForRedeem,
            ),
            ("\"Verified\"", ChallengeState::Verified),
            ("\"Failed\"", ChallengeState::Failed),
            ("\"Expired\"", ChallengeState::Expired),
        ];
        for (json, expected) in cases {
            let decoded: ChallengeState = serde_json::from_str(json)?;
            assert_eq!(decoded, expected);
        }
        Ok(())
    }

    /* ========================================================================== */
    /*                    CIV-132: validate() boundary lengths                   */
    /* ========================================================================== */

    #[test]
    fn test_validate_rp_challenge_31_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 31];
        challenge.submit_secret = vec![0u8; 32];
        challenge.code_challenge_bytes = vec![0u8; 32];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(err.contains("rp_challenge"));
        assert!(err.contains("31"));
        Ok(())
    }

    #[test]
    fn test_validate_rp_challenge_33_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 33];
        challenge.submit_secret = vec![0u8; 32];
        challenge.code_challenge_bytes = vec![0u8; 32];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(err.contains("rp_challenge"));
        assert!(err.contains("33"));
        Ok(())
    }

    #[test]
    fn test_validate_submit_secret_31_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![0u8; 31];
        challenge.code_challenge_bytes = vec![0u8; 32];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(err.contains("submit_secret"));
        assert!(err.contains("31"));
        Ok(())
    }

    #[test]
    fn test_validate_submit_secret_33_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![0u8; 33];
        challenge.code_challenge_bytes = vec![0u8; 32];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(err.contains("submit_secret"));
        assert!(err.contains("33"));
        Ok(())
    }

    #[test]
    fn test_validate_code_challenge_bytes_31() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![0u8; 32];
        challenge.code_challenge_bytes = vec![0u8; 31];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(err.contains("code_challenge_bytes"));
        assert!(err.contains("31"));
        Ok(())
    }

    #[test]
    fn test_validate_code_challenge_bytes_33() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![0u8; 32];
        challenge.code_challenge_bytes = vec![0u8; 33];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(err.contains("code_challenge_bytes"));
        assert!(err.contains("33"));
        Ok(())
    }

    #[test]
    fn test_validate_multiple_fields_wrong_first_error_wins(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // When multiple fields are wrong, rp_challenge is checked first
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 10];
        challenge.submit_secret = vec![0u8; 10];
        challenge.code_challenge_bytes = vec![0u8; 10];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(
            err.contains("rp_challenge"),
            "First failing field should be rp_challenge, got: {}",
            err
        );
        Ok(())
    }

    #[test]
    fn test_validate_submit_secret_wrong_but_rp_ok_second_error(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![0u8; 10];
        challenge.code_challenge_bytes = vec![0u8; 10];
        let err = challenge.validate().err().ok_or("expected error")?;
        assert!(
            err.contains("submit_secret"),
            "Second check should be submit_secret, got: {}",
            err
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge: full roundtrip with all fields        */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_full_roundtrip_all_fields() -> Result<(), Box<dyn std::error::Error>> {
        let challenge = CachedChallenge {
            id: Uuid::new_v4(),
            short_code: "999988887777".to_string(),
            rp_challenge: vec![0xAA; 32],
            cutoff_days: -500,
            verifying_key_id: 42,
            code_challenge: "base64url_challenge_value".to_string(),
            code_challenge_bytes: vec![0xBB; 32],
            submit_secret: vec![0xCC; 32],
            origin: "https://full-roundtrip.example.com".to_string(),
            expires_at: 9999999999,
            created_at: 1111111111,
            state: ChallengeState::ProofOkWaitingForRedeem,
            proof_submitted: true,
            verified_at: Some(2222222222),
            proof_verified_at: Some(3333333333),
            issuer_kid: Some("kid-full-roundtrip".to_string()),
            issuer_vk_bytes: Some([0xDD; 32]),
            client_id: Some("client-full".to_string()),
            tenant_id: Some("tenant-full".to_string()),
            proof_direction: ProofDirection::UnderAge,
        };

        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;

        assert_eq!(challenge.id, decoded.id);
        assert_eq!(challenge.short_code, decoded.short_code);
        assert_eq!(challenge.rp_challenge, decoded.rp_challenge);
        assert_eq!(challenge.cutoff_days, decoded.cutoff_days);
        assert_eq!(challenge.verifying_key_id, decoded.verifying_key_id);
        assert_eq!(challenge.code_challenge, decoded.code_challenge);
        assert_eq!(challenge.code_challenge_bytes, decoded.code_challenge_bytes);
        assert_eq!(challenge.submit_secret, decoded.submit_secret);
        assert_eq!(challenge.origin, decoded.origin);
        assert_eq!(challenge.expires_at, decoded.expires_at);
        assert_eq!(challenge.created_at, decoded.created_at);
        assert_eq!(challenge.state, decoded.state);
        assert_eq!(challenge.proof_submitted, decoded.proof_submitted);
        assert_eq!(challenge.verified_at, decoded.verified_at);
        assert_eq!(challenge.proof_verified_at, decoded.proof_verified_at);
        assert_eq!(challenge.issuer_kid, decoded.issuer_kid);
        assert_eq!(challenge.issuer_vk_bytes, decoded.issuer_vk_bytes);
        assert_eq!(challenge.client_id, decoded.client_id);
        assert_eq!(challenge.tenant_id, decoded.tenant_id);
        assert_eq!(challenge.proof_direction, decoded.proof_direction);
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge: clone preserves optional fields       */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_clone_preserves_all_optionals() {
        let challenge = CachedChallenge {
            id: Uuid::new_v4(),
            short_code: "111122223333".to_string(),
            rp_challenge: vec![1; 32],
            cutoff_days: 100,
            verifying_key_id: 7,
            code_challenge: "cc".to_string(),
            code_challenge_bytes: vec![2; 32],
            submit_secret: vec![3; 32],
            origin: "https://clone-test.com".to_string(),
            expires_at: 5000,
            created_at: 4000,
            state: ChallengeState::Verified,
            proof_submitted: true,
            verified_at: Some(4500),
            proof_verified_at: Some(4200),
            issuer_kid: Some("kid-clone".to_string()),
            issuer_vk_bytes: Some([77u8; 32]),
            client_id: Some("client-clone".to_string()),
            tenant_id: Some("tenant-clone".to_string()),
            proof_direction: ProofDirection::UnderAge,
        };

        let cloned = challenge.clone();
        assert_eq!(challenge.id, cloned.id);
        assert_eq!(challenge.short_code, cloned.short_code);
        assert_eq!(challenge.rp_challenge, cloned.rp_challenge);
        assert_eq!(challenge.code_challenge, cloned.code_challenge);
        assert_eq!(challenge.code_challenge_bytes, cloned.code_challenge_bytes);
        assert_eq!(challenge.submit_secret, cloned.submit_secret);
        assert_eq!(challenge.origin, cloned.origin);
        assert_eq!(challenge.state, cloned.state);
        assert_eq!(challenge.proof_submitted, cloned.proof_submitted);
        assert_eq!(challenge.verified_at, cloned.verified_at);
        assert_eq!(challenge.proof_verified_at, cloned.proof_verified_at);
        assert_eq!(challenge.issuer_kid, cloned.issuer_kid);
        assert_eq!(challenge.issuer_vk_bytes, cloned.issuer_vk_bytes);
        assert_eq!(challenge.client_id, cloned.client_id);
        assert_eq!(challenge.tenant_id, cloned.tenant_id);
        assert_eq!(challenge.proof_direction, cloned.proof_direction);
    }

    /* ========================================================================== */
    /*                    CachedChallenge Debug: all optional fields populated   */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_debug_all_optionals_populated() {
        let challenge = CachedChallenge {
            id: Uuid::new_v4(),
            short_code: "444455556666".to_string(),
            rp_challenge: vec![0xAA; 32],
            cutoff_days: 200,
            verifying_key_id: 3,
            code_challenge: "debug-cc".to_string(),
            code_challenge_bytes: vec![0xBB; 32],
            submit_secret: vec![0xCC; 32],
            origin: "https://debug-all.example.com".to_string(),
            expires_at: 8888,
            created_at: 7777,
            state: ChallengeState::Failed,
            proof_submitted: true,
            verified_at: Some(8000),
            proof_verified_at: Some(7900),
            issuer_kid: Some("kid-debug-all".to_string()),
            issuer_vk_bytes: Some([0xDD; 32]),
            client_id: Some("client-debug".to_string()),
            tenant_id: Some("tenant-debug".to_string()),
            proof_direction: ProofDirection::OverAge,
        };

        let debug = format!("{:?}", challenge);
        // Public fields are shown
        assert!(debug.contains("444455556666"));
        assert!(debug.contains("debug-all.example.com"));
        assert!(debug.contains("Failed"));
        assert!(debug.contains("kid-debug-all"));
        assert!(debug.contains("client-debug"));
        assert!(debug.contains("tenant-debug"));
        assert!(debug.contains("OverAge"));
        // Secret fields are redacted
        assert!(debug.contains("[REDACTED 32 bytes]"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_cached_challenge_debug_shows_client_id_and_tenant_id() {
        let mut challenge = create_test_challenge();
        challenge.client_id = Some("my-client-id".to_string());
        challenge.tenant_id = Some("my-tenant-id".to_string());
        let debug = format!("{:?}", challenge);
        assert!(debug.contains("my-client-id"));
        assert!(debug.contains("my-tenant-id"));
    }

    #[test]
    fn test_cached_challenge_debug_none_optionals() {
        let challenge = create_test_challenge();
        let debug = format!("{:?}", challenge);
        assert!(debug.contains("verified_at: None"));
        assert!(debug.contains("proof_verified_at: None"));
        assert!(debug.contains("issuer_kid: None"));
        assert!(debug.contains("client_id: None"));
        assert!(debug.contains("tenant_id: None"));
    }

    /* ========================================================================== */
    /*                    CachedChallenge: proof_direction values                */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_over_age_direction_roundtrip() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut challenge = create_test_challenge();
        challenge.proof_direction = ProofDirection::OverAge;
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.proof_direction, ProofDirection::OverAge);
        Ok(())
    }

    #[test]
    fn test_cached_challenge_under_age_direction_roundtrip(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.proof_direction = ProofDirection::UnderAge;
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.proof_direction, ProofDirection::UnderAge);
        Ok(())
    }

    #[test]
    fn test_cached_challenge_invalid_proof_direction_rejected() {
        // Now that proof_direction is an enum, invalid values are
        // rejected at deserialisation time rather than silently accepted.
        let challenge = create_test_challenge();
        let json = serde_json::to_string(&challenge).unwrap();
        let json = json.replace("\"over_age\"", "\"custom_direction\"");
        let result = serde_json::from_str::<CachedChallenge>(&json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    CachedChallenge: empty and edge-case strings           */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_empty_short_code_roundtrip() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut challenge = create_test_challenge();
        challenge.short_code = String::new();
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.short_code, "");
        Ok(())
    }

    #[test]
    fn test_cached_challenge_empty_origin_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.origin = String::new();
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.origin, "");
        Ok(())
    }

    #[test]
    fn test_cached_challenge_empty_code_challenge_roundtrip(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.code_challenge = String::new();
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.code_challenge, "");
        Ok(())
    }

    #[test]
    fn test_cached_challenge_unicode_origin_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.origin = "https://\u{00e9}xample.com".to_string();
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.origin, "https://\u{00e9}xample.com");
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge: verifying_key_id edge values          */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_verifying_key_id_zero() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.verifying_key_id = 0;
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.verifying_key_id, 0);
        Ok(())
    }

    #[test]
    fn test_cached_challenge_verifying_key_id_max() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.verifying_key_id = u32::MAX;
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.verifying_key_id, u32::MAX);
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge: issuer_vk_bytes roundtrip             */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_issuer_vk_bytes_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        let vk: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        challenge.issuer_vk_bytes = Some(vk);
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.issuer_vk_bytes, Some(vk));
        Ok(())
    }

    #[test]
    fn test_cached_challenge_issuer_vk_bytes_none_roundtrip(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let challenge = create_test_challenge();
        assert!(challenge.issuer_vk_bytes.is_none());
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert!(decoded.issuer_vk_bytes.is_none());
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge: serde defaults resilience             */
    /* ========================================================================== */

    #[test]
    fn test_all_serde_defaults_together() -> Result<(), Box<dyn std::error::Error>> {
        // Remove all defaulted fields at once
        let challenge = create_test_challenge();
        let mut json_val: serde_json::Value = serde_json::to_value(&challenge)?;
        if let serde_json::Value::Object(ref mut map) = json_val {
            map.remove("proof_direction");
            map.remove("client_id");
            map.remove("tenant_id");
        }
        let decoded: CachedChallenge = serde_json::from_value(json_val)?;
        assert_eq!(decoded.proof_direction, ProofDirection::OverAge);
        assert_eq!(decoded.client_id, None);
        assert_eq!(decoded.tenant_id, None);
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge: validate with empty submit_secret     */
    /*                    in different states                                     */
    /* ========================================================================== */

    #[test]
    fn test_validate_empty_submit_secret_with_verified_state() {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![]; // zeroized after proof
        challenge.code_challenge_bytes = vec![0u8; 32];
        challenge.state = ChallengeState::Verified;
        assert!(challenge.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_submit_secret_with_failed_state() {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![]; // zeroized after proof
        challenge.code_challenge_bytes = vec![0u8; 32];
        challenge.state = ChallengeState::Failed;
        assert!(challenge.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_submit_secret_with_expired_state() {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 32];
        challenge.submit_secret = vec![];
        challenge.code_challenge_bytes = vec![0u8; 32];
        challenge.state = ChallengeState::Expired;
        assert!(challenge.validate().is_ok());
    }

    /* ========================================================================== */
    /*                    CachedChallenge: Drop zeroisation wiring              */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_manual_zeroize_clears_secrets(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = CachedChallenge {
            id: Uuid::new_v4(),
            short_code: "000000000000".to_string(),
            rp_challenge: vec![0xFF; 32],
            cutoff_days: 0,
            verifying_key_id: 0,
            code_challenge: "some_code_challenge".to_string(),
            code_challenge_bytes: vec![0xEE; 32],
            submit_secret: vec![0xDD; 32],
            origin: "https://zeroize.test".to_string(),
            expires_at: 0,
            created_at: 0,
            state: ChallengeState::Pending,
            proof_submitted: false,
            verified_at: None,
            proof_verified_at: None,
            issuer_kid: None,
            issuer_vk_bytes: Some([0xCC; 32]),
            client_id: None,
            tenant_id: None,
            proof_direction: ProofDirection::OverAge,
        };

        // Manually invoke the Drop impl's zeroize logic
        challenge.rp_challenge.zeroize();
        challenge.code_challenge.zeroize();
        challenge.code_challenge_bytes.zeroize();
        challenge.submit_secret.zeroize();
        if let Some(bytes) = challenge.issuer_vk_bytes.as_mut() {
            bytes.zeroize();
        }

        // Verify zeroisation happened
        assert!(challenge.rp_challenge.iter().all(|b| *b == 0));
        assert!(challenge.code_challenge.is_empty());
        assert!(challenge.code_challenge_bytes.iter().all(|b| *b == 0));
        assert!(challenge.submit_secret.iter().all(|b| *b == 0));
        let vk = challenge
            .issuer_vk_bytes
            .as_ref()
            .ok_or("issuer_vk_bytes should still be Some")?;
        assert!(vk.iter().all(|b| *b == 0));

        // Non-secret fields are untouched
        assert_eq!(challenge.origin, "https://zeroize.test");
        assert_eq!(challenge.short_code, "000000000000");
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge: boolean field roundtrips              */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_proof_submitted_false_roundtrip(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.proof_submitted = false;
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert!(!decoded.proof_submitted);
        Ok(())
    }

    #[test]
    fn test_cached_challenge_proof_submitted_true_roundtrip(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.proof_submitted = true;
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert!(decoded.proof_submitted);
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge: short_code format                     */
    /* ========================================================================== */

    #[test]
    fn test_cached_challenge_long_short_code_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.short_code = "9".repeat(100);
        let json = serde_json::to_string(&challenge)?;
        let decoded: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.short_code.len(), 100);
        Ok(())
    }

    /* ========================================================================== */
    /*                    CachedChallenge: validate error message format         */
    /* ========================================================================== */

    #[test]
    fn test_validate_error_includes_actual_and_expected_length(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut challenge = create_test_challenge();
        challenge.rp_challenge = vec![0u8; 16];
        challenge.submit_secret = vec![0u8; 32];
        challenge.code_challenge_bytes = vec![0u8; 32];
        let err = challenge.validate().err().ok_or("expected error")?;
        // Error should contain both the actual length and the expected length
        assert!(
            err.contains("16"),
            "Error should mention actual length 16: {}",
            err
        );
        assert!(
            err.contains("32"),
            "Error should mention expected length 32: {}",
            err
        );
        Ok(())
    }
}
