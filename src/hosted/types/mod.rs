// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Type definitions for hosted verification flows.
//!
//! This module contains all request, response, configuration, and session types
//! used by the hosted routes within provii-verifier. Types are designed for:
//!
//! - Serialisation: Full serde support with validation
//! - SECURITY: Sensitive fields are marked for encryption/zeroisation
//! - Validation: Input validation with serde-valid
//! - Documentation: Rustdoc for all public types
//!
//! # Module Organisation
//!
//! - `requests`: API request types (ChallengeRequest)
//! - `responses`: API response types (ChallengeResponse, StatusResponse, etc.)
//! - `config`: Configuration types (PublicKeyInfo, etc.)
//! - `errors`: Error types with HTTP status code mapping (HostedApiError)
//! - `session`: Session state management (HostedSession, SessionState)
//! - `verification`: provii-verifier integration types

pub mod config;
pub mod errors;
pub mod requests;
pub mod responses;
pub mod session;
pub mod verification;

// Re-export commonly used types
pub use config::PublicKeyInfo;
pub use errors::{HostedApiError, HostedErrorResponse};
pub use requests::ChallengeRequest;
pub use responses::{ChallengeResponse, RedeemResponse, StatusResponse};
pub use session::{HostedSession, SessionState};
pub use verification::{
    AgeProof, ChallengeState, ChallengeStatus, IssuerKey, ProofSubmission, PublicInputs,
    RedeemResult, VerificationResult,
};
