// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Verification types for provii-verifier integration.
//!
//! This module defines types for interacting with the provii-verifier service,
//! including proof submission, verification results, and challenge status.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Proof submission data for POST /v1/verify
///
/// # SECURITY: Memory Zeroisation (ASVS 11.7.1 L3)
///
/// `submit_secret` is zeroised on drop. Debug output redacts it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofSubmission {
    /// Challenge ID (UUID v4)
    pub challenge_id: String,

    /// Submit secret for anti-abuse (base64url-encoded, 32 bytes)
    pub submit_secret: String,

    /// The age proof data
    pub proof: AgeProof,
}

impl std::fmt::Debug for ProofSubmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofSubmission")
            .field("challenge_id", &self.challenge_id)
            .field("submit_secret", &"[REDACTED]")
            .field("proof", &self.proof)
            .finish()
    }
}

impl Drop for ProofSubmission {
    fn drop(&mut self) {
        self.submit_secret.zeroize();
    }
}

/// Age proof structure containing ZK proof and public inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgeProof {
    /// Verifying key ID
    pub verifying_key_id: String,

    /// Public inputs for the proof
    pub public: PublicInputs,

    /// Groth16 proof data (base64url-encoded, 192 bytes)
    pub proof: String,
}

/// Public inputs for the zero-knowledge proof
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicInputs {
    /// Cutoff days representing the age threshold
    pub cutoff_days: i32,

    /// Relying party challenge (base64url-encoded, 32 bytes)
    pub rp_challenge: String,

    /// Issuer public key
    pub issuer: IssuerKey,

    /// Credential nullifier for uniqueness (base64url-encoded, 32 bytes)
    pub cred_nullifier: String,
}

/// Issuer public key wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerKey {
    /// Issuer key value (base64url-encoded, 32 bytes)
    pub value: String,
}

/// Result from proof verification (response from POST /v1/verify)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationResult {
    /// Result status ("success" or "error")
    pub result: String,

    /// Challenge state after verification ("pending", "verified", etc.)
    pub state: String,

    /// Optional error message if verification failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Timestamp when verification occurred (Unix seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,

    /// Whether age verification passed
    #[serde(default)]
    pub age_verified: bool,
}

/// Challenge status from GET /v1/challenge/{id}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeStatus {
    /// Current challenge state
    pub state: ChallengeState,

    /// When the challenge expires (Unix timestamp seconds)
    pub expires_at: u64,

    /// Whether proof has been submitted and verified
    #[serde(default)]
    pub verified: bool,

    /// Optional error message if challenge failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// When the challenge was created (Unix timestamp seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,

    /// When the proof was submitted (Unix timestamp seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_submitted_at: Option<u64>,
}

/// Challenge lifecycle states
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeState {
    /// Challenge created, waiting for proof
    Pending,

    /// Proof submitted and verified successfully
    Verified,

    /// Challenge expired before completion
    Expired,

    /// Proof verification failed
    Failed,

    /// Challenge redeemed
    Redeemed,
}

impl ChallengeState {
    /// Check if the challenge is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ChallengeState::Verified
                | ChallengeState::Expired
                | ChallengeState::Failed
                | ChallengeState::Redeemed
        )
    }

    /// Check if the challenge can be redeemed
    pub fn can_redeem(&self) -> bool {
        matches!(self, ChallengeState::Verified)
    }
}

/// Redemption result from POST /v1/challenge/{id}/redeem
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemResult {
    /// Result status ("success" or "error")
    pub result: String,

    /// Whether the challenge was verified
    pub verified: bool,

    /// Optional error message if redemption failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// When redemption occurred (Unix timestamp seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeemed_at: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_submission_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let submission = ProofSubmission {
            challenge_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            submit_secret: "test_submit_secret".to_string(),
            proof: AgeProof {
                verifying_key_id: "vk-001".to_string(),
                public: PublicInputs {
                    cutoff_days: 6570,
                    rp_challenge: "test_challenge".to_string(),
                    issuer: IssuerKey {
                        value: "test_issuer_key".to_string(),
                    },
                    cred_nullifier: "test_nullifier".to_string(),
                },
                proof: "test_proof_data".to_string(),
            },
        };

        let json = serde_json::to_string(&submission)?;
        assert!(json.contains("challenge_id"));
        assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));
        Ok(())
    }

    #[test]
    fn test_verification_result_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"result":"success","state":"verified","age_verified":true}"#;
        let result: VerificationResult = serde_json::from_str(json)?;
        assert_eq!(result.result, "success");
        assert_eq!(result.state, "verified");
        assert!(result.age_verified);
        Ok(())
    }

    #[test]
    fn test_challenge_status_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"state":"verified","expires_at":1698598800,"verified":true}"#;
        let status: ChallengeStatus = serde_json::from_str(json)?;
        assert_eq!(status.state, ChallengeState::Verified);
        assert_eq!(status.expires_at, 1698598800);
        assert!(status.verified);
        Ok(())
    }

    #[test]
    fn test_challenge_state_terminal() {
        assert!(ChallengeState::Verified.is_terminal());
        assert!(ChallengeState::Expired.is_terminal());
        assert!(ChallengeState::Failed.is_terminal());
        assert!(ChallengeState::Redeemed.is_terminal());
        assert!(!ChallengeState::Pending.is_terminal());
    }

    #[test]
    fn test_challenge_state_can_redeem() {
        assert!(ChallengeState::Verified.can_redeem());
        assert!(!ChallengeState::Pending.can_redeem());
        assert!(!ChallengeState::Expired.can_redeem());
        assert!(!ChallengeState::Failed.can_redeem());
        assert!(!ChallengeState::Redeemed.can_redeem());
    }

    #[test]
    fn test_redeem_result_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"result":"success","verified":true,"redeemed_at":1698512400}"#;
        let result: RedeemResult = serde_json::from_str(json)?;
        assert_eq!(result.result, "success");
        assert!(result.verified);
        assert_eq!(result.redeemed_at, Some(1698512400));
        Ok(())
    }

    // ── ProofSubmission Debug redaction ──────────────────────────────────

    #[test]
    fn test_proof_submission_debug_redacts_secret() {
        let submission = ProofSubmission {
            challenge_id: "challenge-id-123".to_string(),
            submit_secret: "this-should-be-redacted".to_string(),
            proof: AgeProof {
                verifying_key_id: "vk-001".to_string(),
                public: PublicInputs {
                    cutoff_days: 6570,
                    rp_challenge: "ch".to_string(),
                    issuer: IssuerKey {
                        value: "ik".to_string(),
                    },
                    cred_nullifier: "cn".to_string(),
                },
                proof: "proof-data".to_string(),
            },
        };
        let debug = format!("{:?}", submission);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("this-should-be-redacted"));
        assert!(debug.contains("challenge-id-123"));
    }

    // ── ProofSubmission deny_unknown_fields ──────────────────────────────

    #[test]
    fn test_proof_submission_rejects_unknown_fields() {
        let json = r#"{"challenge_id":"id","submit_secret":"s","proof":{"verifying_key_id":"v","public":{"cutoff_days":1,"rp_challenge":"r","issuer":{"value":"i"},"cred_nullifier":"n"},"proof":"p"},"extra":"bad"}"#;
        let result = serde_json::from_str::<ProofSubmission>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── AgeProof deny_unknown_fields ────────────────────────────────────

    #[test]
    fn test_age_proof_rejects_unknown_fields() {
        let json = r#"{"verifying_key_id":"v","public":{"cutoff_days":1,"rp_challenge":"r","issuer":{"value":"i"},"cred_nullifier":"n"},"proof":"p","extra":"bad"}"#;
        let result = serde_json::from_str::<AgeProof>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── PublicInputs deny_unknown_fields ─────────────────────────────────

    #[test]
    fn test_public_inputs_rejects_unknown_fields() {
        let json = r#"{"cutoff_days":1,"rp_challenge":"r","issuer":{"value":"i"},"cred_nullifier":"n","extra":"bad"}"#;
        let result = serde_json::from_str::<PublicInputs>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── IssuerKey deny_unknown_fields ────────────────────────────────────

    #[test]
    fn test_issuer_key_rejects_unknown_fields() {
        let json = r#"{"value":"v","extra":"bad"}"#;
        let result = serde_json::from_str::<IssuerKey>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── ChallengeState serde roundtrip ──────────────────────────────────

    #[test]
    fn test_challenge_state_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let states = vec![
            (ChallengeState::Pending, "\"pending\""),
            (ChallengeState::Verified, "\"verified\""),
            (ChallengeState::Expired, "\"expired\""),
            (ChallengeState::Failed, "\"failed\""),
            (ChallengeState::Redeemed, "\"redeemed\""),
        ];
        for (state, expected_json) in states {
            let json = serde_json::to_string(&state)?;
            assert_eq!(json, expected_json, "serialize {:?}", state);
            let deserialized: ChallengeState = serde_json::from_str(&json)?;
            assert_eq!(deserialized, state, "deserialize {:?}", state);
        }
        Ok(())
    }

    // ── VerificationResult with optional fields ─────────────────────────

    #[test]
    fn test_verification_result_optional_fields_absent() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"result":"error","state":"failed"}"#;
        let result: VerificationResult = serde_json::from_str(json)?;
        assert_eq!(result.result, "error");
        assert_eq!(result.state, "failed");
        assert_eq!(result.error, None);
        assert_eq!(result.timestamp, None);
        assert!(!result.age_verified); // default
        Ok(())
    }

    #[test]
    fn test_verification_result_full() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"result":"success","state":"verified","error":null,"timestamp":1700000000,"age_verified":true}"#;
        let result: VerificationResult = serde_json::from_str(json)?;
        assert_eq!(result.timestamp, Some(1700000000));
        assert!(result.age_verified);
        Ok(())
    }

    #[test]
    fn test_verification_result_rejects_unknown_fields() {
        let json = r#"{"result":"ok","state":"s","extra":"bad"}"#;
        let result = serde_json::from_str::<VerificationResult>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── ChallengeStatus with optional fields ────────────────────────────

    #[test]
    fn test_challenge_status_optional_fields_absent() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"state":"pending","expires_at":999}"#;
        let status: ChallengeStatus = serde_json::from_str(json)?;
        assert_eq!(status.state, ChallengeState::Pending);
        assert_eq!(status.expires_at, 999);
        assert!(!status.verified); // default
        assert_eq!(status.error, None);
        assert_eq!(status.created_at, None);
        assert_eq!(status.proof_submitted_at, None);
        Ok(())
    }

    #[test]
    fn test_challenge_status_rejects_unknown_fields() {
        let json = r#"{"state":"pending","expires_at":1,"extra":"bad"}"#;
        let result = serde_json::from_str::<ChallengeStatus>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── RedeemResult with optional fields ────────────────────────────────

    #[test]
    fn test_redeem_result_no_optional_fields() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"result":"error","verified":false}"#;
        let result: RedeemResult = serde_json::from_str(json)?;
        assert_eq!(result.result, "error");
        assert!(!result.verified);
        assert_eq!(result.error, None);
        assert_eq!(result.redeemed_at, None);
        Ok(())
    }

    #[test]
    fn test_redeem_result_rejects_unknown_fields() {
        let json = r#"{"result":"ok","verified":true,"extra":"bad"}"#;
        let result = serde_json::from_str::<RedeemResult>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── Serialization skip_serializing_if ────────────────────────────────

    #[test]
    fn test_verification_result_skip_none_error() -> Result<(), Box<dyn std::error::Error>> {
        let result = VerificationResult {
            result: "success".to_string(),
            state: "verified".to_string(),
            error: None,
            timestamp: None,
            age_verified: true,
        };
        let json = serde_json::to_string(&result)?;
        assert!(!json.contains("error"), "None error should be omitted");
        assert!(
            !json.contains("timestamp"),
            "None timestamp should be omitted"
        );
        Ok(())
    }

    #[test]
    fn test_challenge_status_skip_none_fields() -> Result<(), Box<dyn std::error::Error>> {
        let status = ChallengeStatus {
            state: ChallengeState::Pending,
            expires_at: 100,
            verified: false,
            error: None,
            created_at: None,
            proof_submitted_at: None,
        };
        let json = serde_json::to_string(&status)?;
        assert!(!json.contains("error"));
        assert!(!json.contains("created_at"));
        assert!(!json.contains("proof_submitted_at"));
        Ok(())
    }

    #[test]
    fn test_redeem_result_skip_none_fields() -> Result<(), Box<dyn std::error::Error>> {
        let result = RedeemResult {
            result: "success".to_string(),
            verified: true,
            error: None,
            redeemed_at: None,
        };
        let json = serde_json::to_string(&result)?;
        assert!(!json.contains("error"));
        assert!(!json.contains("redeemed_at"));
        Ok(())
    }

    // ── ProofSubmission serialisation roundtrip ─────────────────────────

    #[test]
    fn test_proof_submission_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = ProofSubmission {
            challenge_id: "chal-rt".to_string(),
            submit_secret: "secret-rt".to_string(),
            proof: AgeProof {
                verifying_key_id: "vk-rt".to_string(),
                public: PublicInputs {
                    cutoff_days: 6570,
                    rp_challenge: "rp-rt".to_string(),
                    issuer: IssuerKey {
                        value: "ik-rt".to_string(),
                    },
                    cred_nullifier: "cn-rt".to_string(),
                },
                proof: "proof-rt".to_string(),
            },
        };
        let json = serde_json::to_string(&original)?;
        let decoded: ProofSubmission = serde_json::from_str(&json)?;
        assert_eq!(decoded.challenge_id, "chal-rt");
        assert_eq!(decoded.submit_secret, "secret-rt");
        assert_eq!(decoded.proof.verifying_key_id, "vk-rt");
        assert_eq!(decoded.proof.public.cutoff_days, 6570);
        assert_eq!(decoded.proof.public.rp_challenge, "rp-rt");
        assert_eq!(decoded.proof.public.issuer.value, "ik-rt");
        assert_eq!(decoded.proof.public.cred_nullifier, "cn-rt");
        assert_eq!(decoded.proof.proof, "proof-rt");
        Ok(())
    }

    // ── AgeProof serialisation roundtrip ────────────────────────────────

    #[test]
    fn test_age_proof_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = AgeProof {
            verifying_key_id: "vk-001".to_string(),
            public: PublicInputs {
                cutoff_days: 9125,
                rp_challenge: "ch-data".to_string(),
                issuer: IssuerKey {
                    value: "issuer-val".to_string(),
                },
                cred_nullifier: "null-val".to_string(),
            },
            proof: "base64-proof-data".to_string(),
        };
        let json = serde_json::to_string(&original)?;
        let decoded: AgeProof = serde_json::from_str(&json)?;
        assert_eq!(decoded.verifying_key_id, "vk-001");
        assert_eq!(decoded.public.cutoff_days, 9125);
        assert_eq!(decoded.proof, "base64-proof-data");
        Ok(())
    }

    // ── PublicInputs serialisation roundtrip ─────────────────────────────

    #[test]
    fn test_public_inputs_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = PublicInputs {
            cutoff_days: 3650,
            rp_challenge: "challenge-value".to_string(),
            issuer: IssuerKey {
                value: "issuer-key-value".to_string(),
            },
            cred_nullifier: "nullifier-value".to_string(),
        };
        let json = serde_json::to_string(&original)?;
        let decoded: PublicInputs = serde_json::from_str(&json)?;
        assert_eq!(decoded.cutoff_days, 3650);
        assert_eq!(decoded.rp_challenge, "challenge-value");
        assert_eq!(decoded.issuer.value, "issuer-key-value");
        assert_eq!(decoded.cred_nullifier, "nullifier-value");
        Ok(())
    }

    // ── IssuerKey serialisation roundtrip ────────────────────────────────

    #[test]
    fn test_issuer_key_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = IssuerKey {
            value: "test-issuer-key".to_string(),
        };
        let json = serde_json::to_string(&original)?;
        let decoded: IssuerKey = serde_json::from_str(&json)?;
        assert_eq!(decoded.value, "test-issuer-key");
        Ok(())
    }

    // ── VerificationResult serialisation roundtrip ──────────────────────

    #[test]
    fn test_verification_result_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = VerificationResult {
            result: "success".to_string(),
            state: "verified".to_string(),
            error: Some("test error".to_string()),
            timestamp: Some(1700000000),
            age_verified: true,
        };
        let json = serde_json::to_string(&original)?;
        let decoded: VerificationResult = serde_json::from_str(&json)?;
        assert_eq!(decoded.result, "success");
        assert_eq!(decoded.state, "verified");
        assert_eq!(decoded.error.as_deref(), Some("test error"));
        assert_eq!(decoded.timestamp, Some(1700000000));
        assert!(decoded.age_verified);
        Ok(())
    }

    // ── VerificationResult with error message ──────────────────────────

    #[test]
    fn test_verification_result_with_error() -> Result<(), Box<dyn std::error::Error>> {
        let json =
            r#"{"result":"error","state":"failed","error":"Proof invalid","age_verified":false}"#;
        let result: VerificationResult = serde_json::from_str(json)?;
        assert_eq!(result.result, "error");
        assert_eq!(result.state, "failed");
        assert_eq!(result.error.as_deref(), Some("Proof invalid"));
        assert!(!result.age_verified);
        Ok(())
    }

    // ── ChallengeStatus full deserialisation ────────────────────────────

    #[test]
    fn test_challenge_status_full_fields() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"state":"verified","expires_at":9999,"verified":true,"error":null,"created_at":1000,"proof_submitted_at":2000}"#;
        let status: ChallengeStatus = serde_json::from_str(json)?;
        assert_eq!(status.state, ChallengeState::Verified);
        assert_eq!(status.expires_at, 9999);
        assert!(status.verified);
        assert!(status.error.is_none());
        assert_eq!(status.created_at, Some(1000));
        assert_eq!(status.proof_submitted_at, Some(2000));
        Ok(())
    }

    // ── ChallengeStatus with error ──────────────────────────────────────

    #[test]
    fn test_challenge_status_with_error() -> Result<(), Box<dyn std::error::Error>> {
        let json =
            r#"{"state":"failed","expires_at":500,"verified":false,"error":"Invalid proof data"}"#;
        let status: ChallengeStatus = serde_json::from_str(json)?;
        assert_eq!(status.state, ChallengeState::Failed);
        assert!(!status.verified);
        assert_eq!(status.error.as_deref(), Some("Invalid proof data"));
        Ok(())
    }

    // ── ChallengeStatus serialisation roundtrip ─────────────────────────

    #[test]
    fn test_challenge_status_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = ChallengeStatus {
            state: ChallengeState::Redeemed,
            expires_at: 8888,
            verified: true,
            error: None,
            created_at: Some(7777),
            proof_submitted_at: Some(7800),
        };
        let json = serde_json::to_string(&original)?;
        let decoded: ChallengeStatus = serde_json::from_str(&json)?;
        assert_eq!(decoded.state, ChallengeState::Redeemed);
        assert_eq!(decoded.expires_at, 8888);
        assert!(decoded.verified);
        assert_eq!(decoded.created_at, Some(7777));
        assert_eq!(decoded.proof_submitted_at, Some(7800));
        Ok(())
    }

    // ── ChallengeState all states serde ─────────────────────────────────

    #[test]
    fn test_challenge_state_all_lowercase_serde() -> Result<(), Box<dyn std::error::Error>> {
        // Verify all variants serialize to lowercase
        assert_eq!(
            serde_json::to_string(&ChallengeState::Pending)?,
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&ChallengeState::Verified)?,
            "\"verified\""
        );
        assert_eq!(
            serde_json::to_string(&ChallengeState::Expired)?,
            "\"expired\""
        );
        assert_eq!(
            serde_json::to_string(&ChallengeState::Failed)?,
            "\"failed\""
        );
        assert_eq!(
            serde_json::to_string(&ChallengeState::Redeemed)?,
            "\"redeemed\""
        );
        Ok(())
    }

    // ── ChallengeState equality ────────────────────────────────────────

    #[test]
    fn test_challenge_state_equality() {
        assert_eq!(ChallengeState::Pending, ChallengeState::Pending);
        assert_ne!(ChallengeState::Pending, ChallengeState::Verified);
    }

    #[test]
    fn test_challenge_state_clone_copy() {
        let state = ChallengeState::Verified;
        let cloned = state;
        let copied = state;
        assert_eq!(state, cloned);
        assert_eq!(state, copied);
    }

    // ── RedeemResult serialisation roundtrip ────────────────────────────

    #[test]
    fn test_redeem_result_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = RedeemResult {
            result: "success".to_string(),
            verified: true,
            error: None,
            redeemed_at: Some(1700000000),
        };
        let json = serde_json::to_string(&original)?;
        let decoded: RedeemResult = serde_json::from_str(&json)?;
        assert_eq!(decoded.result, "success");
        assert!(decoded.verified);
        assert!(decoded.error.is_none());
        assert_eq!(decoded.redeemed_at, Some(1700000000));
        Ok(())
    }

    #[test]
    fn test_redeem_result_with_error() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"result":"error","verified":false,"error":"Already redeemed"}"#;
        let result: RedeemResult = serde_json::from_str(json)?;
        assert_eq!(result.result, "error");
        assert!(!result.verified);
        assert_eq!(result.error.as_deref(), Some("Already redeemed"));
        assert!(result.redeemed_at.is_none());
        Ok(())
    }

    // ── ProofSubmission with negative cutoff_days ───────────────────────

    #[test]
    fn test_proof_submission_negative_cutoff() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"challenge_id":"c","submit_secret":"s","proof":{"verifying_key_id":"v","public":{"cutoff_days":-1,"rp_challenge":"r","issuer":{"value":"i"},"cred_nullifier":"n"},"proof":"p"}}"#;
        let submission: ProofSubmission = serde_json::from_str(json)?;
        assert_eq!(submission.proof.public.cutoff_days, -1);
        Ok(())
    }

    #[test]
    fn test_proof_submission_zero_cutoff() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"challenge_id":"c","submit_secret":"s","proof":{"verifying_key_id":"v","public":{"cutoff_days":0,"rp_challenge":"r","issuer":{"value":"i"},"cred_nullifier":"n"},"proof":"p"}}"#;
        let submission: ProofSubmission = serde_json::from_str(json)?;
        assert_eq!(submission.proof.public.cutoff_days, 0);
        Ok(())
    }

    // ── ChallengeState is_terminal and can_redeem for all variants ──────

    #[test]
    fn test_challenge_state_is_terminal_exhaustive() {
        assert!(!ChallengeState::Pending.is_terminal());
        assert!(ChallengeState::Verified.is_terminal());
        assert!(ChallengeState::Expired.is_terminal());
        assert!(ChallengeState::Failed.is_terminal());
        assert!(ChallengeState::Redeemed.is_terminal());
    }

    #[test]
    fn test_challenge_state_can_redeem_exhaustive() {
        assert!(!ChallengeState::Pending.can_redeem());
        assert!(ChallengeState::Verified.can_redeem());
        assert!(!ChallengeState::Expired.can_redeem());
        assert!(!ChallengeState::Failed.can_redeem());
        assert!(!ChallengeState::Redeemed.can_redeem());
    }

    // ── Verification result with all fields serialised ──────────────────

    #[test]
    fn test_verification_result_includes_present_optional_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = VerificationResult {
            result: "success".to_string(),
            state: "verified".to_string(),
            error: Some("soft warning".to_string()),
            timestamp: Some(12345),
            age_verified: true,
        };
        let json = serde_json::to_string(&result)?;
        assert!(json.contains("error"));
        assert!(json.contains("soft warning"));
        assert!(json.contains("timestamp"));
        assert!(json.contains("12345"));
        Ok(())
    }

    // ── ChallengeStatus includes present optional fields ────────────────

    #[test]
    fn test_challenge_status_includes_present_optional_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let status = ChallengeStatus {
            state: ChallengeState::Verified,
            expires_at: 100,
            verified: true,
            error: Some("warn".to_string()),
            created_at: Some(50),
            proof_submitted_at: Some(75),
        };
        let json = serde_json::to_string(&status)?;
        assert!(json.contains("error"));
        assert!(json.contains("created_at"));
        assert!(json.contains("proof_submitted_at"));
        Ok(())
    }

    // ── RedeemResult includes present optional fields ───────────────────

    #[test]
    fn test_redeem_result_includes_present_optional_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = RedeemResult {
            result: "success".to_string(),
            verified: true,
            error: Some("note".to_string()),
            redeemed_at: Some(9999),
        };
        let json = serde_json::to_string(&result)?;
        assert!(json.contains("error"));
        assert!(json.contains("note"));
        assert!(json.contains("redeemed_at"));
        assert!(json.contains("9999"));
        Ok(())
    }

    // ── ChallengeState invalid deserialisation ──────────────────────────

    #[test]
    fn test_challenge_state_invalid_value_rejected() {
        let json = r#""unknown_state""#;
        let result = serde_json::from_str::<ChallengeState>(json);
        assert!(result.is_err(), "unknown state variant should be rejected");
    }

    // ── ProofSubmission clone preserves all fields ──────────────────────

    #[test]
    fn test_proof_submission_clone() {
        let original = ProofSubmission {
            challenge_id: "c-clone".to_string(),
            submit_secret: "s-clone".to_string(),
            proof: AgeProof {
                verifying_key_id: "vk".to_string(),
                public: PublicInputs {
                    cutoff_days: 100,
                    rp_challenge: "rp".to_string(),
                    issuer: IssuerKey {
                        value: "ik".to_string(),
                    },
                    cred_nullifier: "cn".to_string(),
                },
                proof: "pr".to_string(),
            },
        };
        let cloned = original.clone();
        assert_eq!(cloned.challenge_id, "c-clone");
        assert_eq!(cloned.submit_secret, "s-clone");
        assert_eq!(cloned.proof.verifying_key_id, "vk");
    }
}
