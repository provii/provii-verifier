// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! HTTP route modules re-exported for the worker router.
//!
//! Each sub-module owns a single endpoint group. Public types and handler
//! functions are re-exported here so callers can import from `routes::` directly.

/// Shared API key authentication logic (PG-VAL-016).
pub(crate) mod api_key_auth;
/// Challenge creation, lookup, and polling routes.
pub mod challenge;
/// Content Security Policy violation report ingestion.
pub mod csp_report;
/// Liveness and readiness health checks.
pub mod health;
/// Rotation-drill admin endpoints. Backs the verify-rotation soak checks
/// and the `cleanup-test-fixtures` CLI in Wave 2.
pub mod internal_admin;
/// Push-invalidation of the JWKS issuer registry cache.
pub mod internal_invalidate_jwks;
/// Rotation framework `/_internal/version` endpoint (P3-05a2).
pub mod internal_version;
/// OpenAPI schema generation endpoint.
pub mod openapi;
/// Shared BOLA ownership verification (OWASP API1:2023).
pub mod ownership;
/// Token redemption (final step after proof verification).
pub mod redeem;
/// Pure schema-inference helpers for structured error localisation (PG-VAL-016).
pub(crate) mod schema_inference;
/// Zero knowledge proof submission and verification.
pub mod verify;

pub use challenge::{
    create_challenge, get_challenge_by_short_code, get_challenge_details, poll_challenge,
    ChallengeDetailsResponse, CreateChallengeRequest, ShortCodeChallengeResponse,
};
pub use csp_report::{handle_csp_report, CspReport};
pub use health::{health_check_basic, health_check_detailed, BasicHealthResponse};
pub use redeem::{redeem_challenge, RedeemRequest};
pub use verify::{submit_verification, SubmitProofRequest};
