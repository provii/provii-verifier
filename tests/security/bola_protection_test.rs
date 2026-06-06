// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust
//! BOLA (Broken Object Level Authorisation) Protection Tests
//!
//! These tests exercise the **production** `verify_ownership` function from
//! `src/routes/ownership.rs` to confirm that object-level authorisation is
//! enforced (OWASP API1:2023, CWE-639, ASVS V8.2.2).
//!
//! Test Coverage:
//! - User A cannot access User B's challenges
//! - Organisation X cannot access Organisation Y's challenges
//! - Missing authentication is rejected
//! - Missing ownership information is rejected
//! - Cross-tenant isolation is enforced

#![cfg(test)]
#![allow(clippy::indexing_slicing)]

use provii_audit::{AuditLogger as SharedLogger, PrivacyContext};
use provii_verifier::routes::ownership::verify_ownership;
use provii_verifier::security::audit::AuditLogger;
use std::sync::Arc;

/// Construct a minimal AuditLogger suitable for test use.
fn test_logger() -> AuditLogger {
    let salt = b"test-salt-minimum-32-bytes-long!!".to_vec();
    let privacy = Arc::new(PrivacyContext::new(salt).expect("valid salt"));
    let inner = SharedLogger::new(None, privacy, "bola-test");
    AuditLogger::new(inner, "test".to_string(), "0.0.0".to_string())
}

// ============================================================================
// BOLA Protection Tests - Cross-Client Access Prevention
// ============================================================================

#[tokio::test]
async fn test_bola_client_a_cannot_access_client_b_challenge() {
    let logger = test_logger();
    let result = verify_ownership(
        Some("client_b"),
        Some("client_a"),
        "chall-bola-001",
        "test_route",
        &logger,
        "127.0.0.1",
        "bola_test_event",
    )
    .await;

    assert!(
        result.is_err(),
        "Client A should NOT be able to access Client B's challenge"
    );
}

#[tokio::test]
async fn test_bola_client_can_access_own_challenge() {
    let logger = test_logger();
    let result = verify_ownership(
        Some("client_a"),
        Some("client_a"),
        "chall-bola-002",
        "test_route",
        &logger,
        "127.0.0.1",
        "bola_test_event",
    )
    .await;

    assert!(
        result.is_ok(),
        "Client should be able to access their own challenge"
    );
}

#[tokio::test]
async fn test_bola_different_clients_isolated() {
    let logger = test_logger();

    // Client A can access their own challenge
    assert!(
        verify_ownership(
            Some("client_a"),
            Some("client_a"),
            "chall-iso-1",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_ok()
    );

    // Client B can access their own challenge
    assert!(
        verify_ownership(
            Some("client_b"),
            Some("client_b"),
            "chall-iso-2",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_ok()
    );

    // Client A CANNOT access Client B's challenge
    assert!(
        verify_ownership(
            Some("client_b"),
            Some("client_a"),
            "chall-iso-3",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_err()
    );

    // Client B CANNOT access Client A's challenge
    assert!(
        verify_ownership(
            Some("client_a"),
            Some("client_b"),
            "chall-iso-4",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn test_bola_multiple_clients_full_isolation() {
    let logger = test_logger();
    let clients = vec!["org_alpha", "org_beta", "org_gamma", "org_delta"];

    for owner in &clients {
        for requester in &clients {
            let result = verify_ownership(
                Some(owner),
                Some(requester),
                "chall-multi",
                "test",
                &logger,
                "127.0.0.1",
                "test",
            )
            .await;

            if owner == requester {
                assert!(
                    result.is_ok(),
                    "{} should access their own challenge",
                    requester
                );
            } else {
                assert!(
                    result.is_err(),
                    "{} should NOT access {}'s challenge",
                    requester,
                    owner
                );
            }
        }
    }
}

// ============================================================================
// BOLA Protection Tests - Missing Ownership (No Backward Compatibility)
// ============================================================================

#[tokio::test]
async fn test_bola_unowned_challenge_rejected() {
    let logger = test_logger();
    let result = verify_ownership(
        None,
        Some("any_client"),
        "chall-unowned",
        "test",
        &logger,
        "127.0.0.1",
        "test",
    )
    .await;

    assert!(
        result.is_err(),
        "Challenges without owner MUST be rejected (no backward compatibility)"
    );
}

#[tokio::test]
async fn test_bola_no_backward_compatibility_bypass() {
    let logger = test_logger();

    // Try multiple different clients against an unowned challenge. All must be rejected.
    for client in &["client_a", "client_b", "admin", "superuser"] {
        let result = verify_ownership(
            None,
            Some(client),
            "chall-no-compat",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await;
        assert!(
            result.is_err(),
            "Unowned challenge should be rejected for client: {}",
            client
        );
    }
}

#[tokio::test]
async fn test_bola_empty_client_id_rejected() {
    let logger = test_logger();
    let result = verify_ownership(
        Some(""),
        Some("valid_client"),
        "chall-empty-owner",
        "test",
        &logger,
        "127.0.0.1",
        "test",
    )
    .await;
    assert!(
        result.is_err(),
        "Empty client_id should not match any requester"
    );
}

// ============================================================================
// BOLA Protection Tests - Case Sensitivity and Exact Matching
// ============================================================================

#[tokio::test]
async fn test_bola_case_sensitive_client_ids() {
    let logger = test_logger();

    // Exact match should succeed
    assert!(
        verify_ownership(
            Some("ClientA"),
            Some("ClientA"),
            "chall-case-1",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_ok()
    );

    // Case mismatches should fail
    for wrong in &["clienta", "CLIENTA", "cLiEnTa"] {
        assert!(
            verify_ownership(
                Some("ClientA"),
                Some(wrong),
                "chall-case-2",
                "test",
                &logger,
                "127.0.0.1",
                "test",
            )
            .await
            .is_err(),
            "Case mismatch '{}' should be rejected",
            wrong
        );
    }
}

#[tokio::test]
async fn test_bola_exact_string_matching() {
    let logger = test_logger();

    // Exact match works
    assert!(
        verify_ownership(
            Some("client_123"),
            Some("client_123"),
            "chall-exact-1",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_ok()
    );

    // Substring attacks should fail
    for wrong in &["client", "client_12", "client_1234", "123"] {
        assert!(
            verify_ownership(
                Some("client_123"),
                Some(wrong),
                "chall-exact-2",
                "test",
                &logger,
                "127.0.0.1",
                "test",
            )
            .await
            .is_err(),
            "Substring '{}' should be rejected",
            wrong
        );
    }
}

#[tokio::test]
async fn test_bola_whitespace_sensitive() {
    let logger = test_logger();

    assert!(
        verify_ownership(
            Some("client_a"),
            Some("client_a"),
            "chall-ws-1",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_ok()
    );
    for wrong in &[" client_a", "client_a ", " client_a "] {
        assert!(
            verify_ownership(
                Some("client_a"),
                Some(wrong),
                "chall-ws-2",
                "test",
                &logger,
                "127.0.0.1",
                "test",
            )
            .await
            .is_err(),
            "Whitespace variant '{}' should be rejected",
            wrong
        );
    }
}

// ============================================================================
// BOLA Protection Tests - Special Characters and Edge Cases
// ============================================================================

#[tokio::test]
async fn test_bola_special_characters_in_client_id() {
    let logger = test_logger();
    let special_ids = vec![
        "client@example.com",
        "client-with-dashes",
        "client_with_underscores",
        "client.with.dots",
        "client:with:colons",
    ];

    for client_id in special_ids {
        assert!(
            verify_ownership(
                Some(client_id),
                Some(client_id),
                "chall-special",
                "test",
                &logger,
                "127.0.0.1",
                "test",
            )
            .await
            .is_ok(),
            "Should match client_id with special chars: {}",
            client_id
        );

        assert!(
            verify_ownership(
                Some(client_id),
                Some("different_client"),
                "chall-special-2",
                "test",
                &logger,
                "127.0.0.1",
                "test",
            )
            .await
            .is_err(),
            "Should reject different client for: {}",
            client_id
        );
    }
}

#[tokio::test]
async fn test_bola_very_long_client_id() {
    let logger = test_logger();
    let long_id = "a".repeat(1000);

    assert!(
        verify_ownership(
            Some(&long_id),
            Some(&long_id),
            "chall-long",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_ok()
    );
    assert!(
        verify_ownership(
            Some(&long_id),
            Some("different"),
            "chall-long-2",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_err()
    );
}

// ============================================================================
// BOLA Protection Tests - Organisation Isolation Scenarios
// ============================================================================

#[tokio::test]
async fn test_bola_organisation_isolation_basic() {
    let logger = test_logger();

    // Organisation X can access their challenge
    assert!(
        verify_ownership(
            Some("org_x"),
            Some("org_x"),
            "chall-org-1",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_ok()
    );

    // Organisation Y can access their challenge
    assert!(
        verify_ownership(
            Some("org_y"),
            Some("org_y"),
            "chall-org-2",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_ok()
    );

    // Cross-access is denied
    assert!(
        verify_ownership(
            Some("org_y"),
            Some("org_x"),
            "chall-org-3",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_err()
    );
    assert!(
        verify_ownership(
            Some("org_x"),
            Some("org_y"),
            "chall-org-4",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn test_bola_similar_organisation_names_isolated() {
    let logger = test_logger();
    let orgs = vec!["acme_corp", "acme_corp_dev", "acme_corporation", "acme"];

    for (i, owner) in orgs.iter().enumerate() {
        for (j, requester) in orgs.iter().enumerate() {
            let result = verify_ownership(
                Some(owner),
                Some(requester),
                "chall-similar",
                "test",
                &logger,
                "127.0.0.1",
                "test",
            )
            .await;

            if i == j {
                assert!(result.is_ok(), "{} should access their own", requester);
            } else {
                assert!(
                    result.is_err(),
                    "{} should NOT access {}'s challenge",
                    requester,
                    owner
                );
            }
        }
    }
}

// ============================================================================
// BOLA Protection Tests - Admin/Privileged Access
// ============================================================================

#[tokio::test]
async fn test_bola_admin_cannot_bypass_without_ownership() {
    let logger = test_logger();

    // SECURITY: Even "admin" or "superuser" cannot bypass BOLA protection
    for privileged in &["admin", "superuser", "root"] {
        assert!(
            verify_ownership(
                Some("regular_user"),
                Some(privileged),
                "chall-admin",
                "test",
                &logger,
                "127.0.0.1",
                "test",
            )
            .await
            .is_err(),
            "{} should NOT bypass BOLA without ownership",
            privileged
        );
    }
}

#[tokio::test]
async fn test_bola_system_accounts_no_special_access() {
    let logger = test_logger();
    let system_accounts = vec!["system", "service", "internal", "api", "automation"];

    for account in system_accounts {
        assert!(
            verify_ownership(
                Some("user_123"),
                Some(account),
                "chall-sys",
                "test",
                &logger,
                "127.0.0.1",
                "test",
            )
            .await
            .is_err(),
            "System account '{}' should NOT have special access",
            account
        );
    }
}

// ============================================================================
// BOLA Protection Tests - Missing Authenticated Client
// ============================================================================

#[tokio::test]
async fn test_bola_no_authenticated_client_rejected() {
    let logger = test_logger();
    let result = verify_ownership(
        Some("owner"),
        None,
        "chall-no-auth",
        "test",
        &logger,
        "127.0.0.1",
        "test",
    )
    .await;
    assert!(
        result.is_err(),
        "Challenge with owner but no authenticated client must be rejected"
    );
}

#[tokio::test]
async fn test_bola_both_none_rejected() {
    let logger = test_logger();
    let result = verify_ownership(
        None,
        None,
        "chall-both-none",
        "test",
        &logger,
        "127.0.0.1",
        "test",
    )
    .await;
    assert!(
        result.is_err(),
        "Both owner and client being None must be rejected"
    );
}

// ============================================================================
// BOLA Protection Tests - Compliance Verification
// ============================================================================

#[tokio::test]
async fn test_bola_owasp_asvs_v8_2_2_compliance() {
    let logger = test_logger();

    // 1. Owner can access their own resource
    assert!(
        verify_ownership(
            Some("owner"),
            Some("owner"),
            "chall-asvs-1",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_ok(),
        "V8.2.2: Owner must be able to access their resource"
    );

    // 2. Non-owner cannot access resource
    assert!(
        verify_ownership(
            Some("owner"),
            Some("other"),
            "chall-asvs-2",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_err(),
        "V8.2.2: Non-owner must be denied access"
    );

    // 3. Resources without ownership must be rejected (no backward compatibility)
    assert!(
        verify_ownership(
            None,
            Some("any"),
            "chall-asvs-3",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_err(),
        "V8.2.2: Resources without ownership must be rejected"
    );

    // 4. Owned resource with no authenticated client must be rejected
    assert!(
        verify_ownership(
            Some("owner"),
            None,
            "chall-asvs-4",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_err(),
        "V8.2.2: No authenticated client must be denied"
    );
}

#[tokio::test]
async fn test_bola_cwe_639_compliance() {
    let logger = test_logger();

    // CWE-639: Authorisation Bypass Through User-Controlled Key
    // Knowing the challenge ID is not sufficient for access
    assert!(
        verify_ownership(
            Some("victim"),
            Some("attacker"),
            "chall-cwe639",
            "test",
            &logger,
            "127.0.0.1",
            "test",
        )
        .await
        .is_err(),
        "CWE-639: Knowledge of resource ID should not grant access"
    );
}
