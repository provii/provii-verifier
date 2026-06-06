// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Shared BOLA ownership verification for challenge endpoints.
//!
//! Enforces OWASP API1:2023 (Broken Object Level Authorisation) by verifying
//! that the authenticated client_id matches the challenge owner. Used by
//! verify, redeem, and poll_challenge routes.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use crate::security::log_sanitizer::redact_challenge_id;
#[cfg(target_arch = "wasm32")]
use worker::console_log;

use subtle::ConstantTimeEq;

use crate::{error::ApiError, security::audit::AuditLogger};

/// Verifies that the authenticated client owns the specified challenge.
///
/// Returns `Ok(())` when ownership is confirmed. Returns
/// `Err(ApiError::Forbidden)` and logs an audit event on mismatch or when the
/// challenge has no recorded owner.
///
/// # Arguments
///
/// * `challenge_owner_id` - The `client_id` stored on the challenge record.
/// * `authenticated_client_id` - The `client_id` extracted from request auth.
/// * `challenge_id` - Used only for redacted log output.
/// * `route_label` - Identifies the calling route in log lines (e.g. "submit_verification").
/// * `audit_logger` - Structured audit event emitter.
/// * `client_ip` - Raw client IP for audit logging.
/// * `audit_event_name` - The event name passed to `log_suspicious_activity` on failure.
pub(crate) async fn verify_ownership(
    challenge_owner_id: Option<&str>,
    authenticated_client_id: Option<&str>,
    _challenge_id: &str,
    _route_label: &str,
    audit_logger: &AuditLogger,
    client_ip: &str,
    audit_event_name: &str,
) -> Result<(), ApiError> {
    match (challenge_owner_id, authenticated_client_id) {
        (Some(owner), Some(client))
            if owner.len() == client.len()
                && bool::from(owner.as_bytes().ct_eq(client.as_bytes())) =>
        {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] {}: Ownership verified for challenge {}",
                _route_label,
                redact_challenge_id(_challenge_id)
            );
            Ok(())
        }
        (Some(_), Some(_)) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] {}: Ownership verification failed for challenge {} (ownership mismatch)",
                _route_label,
                redact_challenge_id(_challenge_id)
            );
            audit_logger
                .log_suspicious_activity(client_ip, audit_event_name)
                .await;
            Err(ApiError::Forbidden(Some(
                "Access denied: you do not own this challenge".into(),
            )))
        }
        (None, _) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] {}: Ownership verification failed for challenge {} (no owner)",
                _route_label,
                redact_challenge_id(_challenge_id)
            );
            audit_logger
                .log_suspicious_activity(client_ip, audit_event_name)
                .await;
            Err(ApiError::Forbidden(Some(
                "Access denied: challenge ownership not established".into(),
            )))
        }
        (Some(_), None) => {
            // Challenge has an owner but no authenticated client_id was provided.
            // Treat as ownership mismatch.
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] {}: Ownership verification failed for challenge {} (no authenticated client)",
                _route_label,
                redact_challenge_id(_challenge_id)
            );
            audit_logger
                .log_suspicious_activity(client_ip, audit_event_name)
                .await;
            Err(ApiError::Forbidden(Some(
                "Access denied: you do not own this challenge".into(),
            )))
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use provii_audit::{AuditLogger as SharedLogger, PrivacyContext};
    use std::sync::Arc;

    fn test_logger() -> AuditLogger {
        let salt = b"test-salt-minimum-32-bytes-long!!".to_vec();
        let privacy = Arc::new(PrivacyContext::new(salt).expect("valid salt"));
        let inner = SharedLogger::new(None, privacy, "ownership-test");
        AuditLogger::new(inner, "test".to_string(), "0.0.0".to_string())
    }

    #[tokio::test]
    async fn test_owner_matches_client_succeeds() {
        let logger = test_logger();
        let result = verify_ownership(
            Some("client-abc"),
            Some("client-abc"),
            "chall-001",
            "test_route",
            &logger,
            "127.0.0.1",
            "test_event",
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_owner_mismatch_returns_forbidden() {
        let logger = test_logger();
        let result = verify_ownership(
            Some("client-abc"),
            Some("client-xyz"),
            "chall-002",
            "test_route",
            &logger,
            "127.0.0.1",
            "test_event",
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ApiError::Forbidden(_)));
    }

    #[tokio::test]
    async fn test_no_owner_returns_forbidden() {
        let logger = test_logger();
        let result = verify_ownership(
            None,
            Some("client-abc"),
            "chall-003",
            "test_route",
            &logger,
            "127.0.0.1",
            "test_event",
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ApiError::Forbidden(_)));
    }

    #[tokio::test]
    async fn test_owner_but_no_client_returns_forbidden() {
        let logger = test_logger();
        let result = verify_ownership(
            Some("client-abc"),
            None,
            "chall-004",
            "test_route",
            &logger,
            "127.0.0.1",
            "test_event",
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ApiError::Forbidden(_)));
    }

    #[tokio::test]
    async fn test_both_none_returns_forbidden() {
        let logger = test_logger();
        let result = verify_ownership(
            None,
            None,
            "chall-005",
            "test_route",
            &logger,
            "127.0.0.1",
            "test_event",
        )
        .await;
        assert!(result.is_err());
    }
}
