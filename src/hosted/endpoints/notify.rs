// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Direct proof notification for hosted verification sessions.
//!
//! Replaces the former service binding call to provii-verifier's
//! `POST /v1/internal/notify`. Now that provii-verifier is merged into
//! provii-verifier, the notification is a direct function call that:
//!
//! 1. Looks up `challenge_to_session:{challenge_id}` in `HOSTED_SESSIONS` KV
//! 2. Updates the session state to `ProofOk` in KV
//! 3. Forwards to `HOSTED_CHALLENGE_NOTIFY_DO` for WebSocket push
//!
//! The function is fire-and-forget: failures are logged but never propagated.
//! The caller (verify.rs) invokes it via `ctx.wait_until()` so it runs after
//! the HTTP response is returned to the wallet.
#![forbid(unsafe_code)]

use crate::hosted::storage::kv::{get_session_kv, update_session_kv_checked};
use crate::hosted::types::session::SessionState;
use crate::AppState;
#[cfg(target_arch = "wasm32")]
use worker::console_log;

/// Notify hosted session that a proof has been verified.
///
/// This is the direct replacement for the former service binding call to
/// `POST /v1/internal/notify` on provii-verifier. Best-effort: failures are
/// logged but never propagated to the caller.
///
/// Looks up `challenge_to_session:{challenge_id}` in HOSTED_SESSIONS KV,
/// loads the session, updates its state to `ProofOk`, writes it back,
/// then forwards to `HOSTED_CHALLENGE_NOTIFY_DO` so connected WebSocket
/// clients receive the status change immediately.
///
/// TODO(testing): ADV-VA-06-012 -- notification flow (KV lookup, session
/// state update, DO forwarding) lacks integration tests.
pub async fn notify_proof_verified(state: &AppState, challenge_id: &str) {
    // Step 1: Look up challenge_id -> session_id mapping in HOSTED_SESSIONS KV.
    let session_id = match lookup_session_for_challenge(&state.env, challenge_id).await {
        Some(sid) => sid,
        None => {
            // No mapping means this challenge was not created via the hosted flow.
            // This is normal for direct API challenges. Silently return.
            #[cfg(target_arch = "wasm32")]
            console_log!("[notify] No hosted session mapping for challenge (non-hosted flow)");
            return;
        }
    };

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[notify] Found session {} for challenge, updating state to ProofOk",
        session_id.get(..8).unwrap_or(&session_id)
    );

    // Step 2: Load and update the session state in KV.
    if let Err(_e) = update_session_state(&state.env, &session_id).await {
        #[cfg(target_arch = "wasm32")]
        console_log!("[notify] Failed to update session state: {}", _e);
        // Continue to WebSocket push anyway; the browser SDK will poll and
        // discover the state change via the challenge store.
    }

    // Step 3: Forward to HOSTED_CHALLENGE_NOTIFY_DO for WebSocket push.
    if let Err(_e) = push_ws_notification(&state.env, &session_id).await {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[notify] WebSocket push failed (client will fall back to polling): {}",
            _e
        );
    }
}

/// Notify hosted session that a proof has failed (age_not_met or simulation
/// failure).
///
/// Mirrors [`notify_proof_verified`] but transitions the hosted session to
/// `Expired` and pushes a WebSocket notification with state `"expired"`.
/// Best-effort: failures are logged but never propagated to the caller.
///
/// TODO(testing): ADV-VA-06-012 -- same integration test gap as
/// `notify_proof_verified`.
pub async fn notify_proof_failed(state: &AppState, challenge_id: &str) {
    let session_id = match lookup_session_for_challenge(&state.env, challenge_id).await {
        Some(sid) => sid,
        None => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[notify] No hosted session mapping for challenge (non-hosted flow)");
            return;
        }
    };

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[notify] Found session {} for challenge, updating state to Expired (proof failed)",
        session_id.get(..8).unwrap_or(&session_id)
    );

    // Transition the session to Expired.
    if let Err(_e) = update_session_state_expired(&state.env, &session_id).await {
        #[cfg(target_arch = "wasm32")]
        console_log!("[notify] Failed to update session state to Expired: {}", _e);
    }

    // Push WebSocket notification with "expired" state.
    if let Err(_e) = push_ws_notification_expired(&state.env, &session_id).await {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[notify] WebSocket push (expired) failed (client will fall back to polling): {}",
            _e
        );
    }
}

/// Look up the session_id for a given challenge_id in HOSTED_SESSIONS KV.
///
/// Returns `None` if the mapping does not exist (non-hosted challenge).
async fn lookup_session_for_challenge(env: &worker::Env, challenge_id: &str) -> Option<String> {
    let kv = match env.kv("HOSTED_SESSIONS") {
        Ok(kv) => kv,
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[notify] HOSTED_SESSIONS KV binding unavailable: {:?}", _e);
            return None;
        }
    };

    // Per-operation timeout for challenge-to-session KV lookup.
    let key = format!("challenge_to_session:{}", challenge_id);
    let kv_clone = kv.clone();
    let key_clone = key.clone();
    match crate::utils::timeout::with_timeout(
        "notify challenge_to_session KV read",
        crate::utils::timeout::KV_READ_TIMEOUT_MS,
        async move { kv_clone.get(&key_clone).text().await },
    )
    .await
    {
        Ok(Ok(Some(session_id))) => Some(session_id),
        Ok(Ok(None)) => None,
        Ok(Err(_e)) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[notify] KV lookup failed for {}: {:?}", key, _e);
            None
        }
        Err(_timeout_err) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[notify] KV lookup timed out for {}: {}", key, _timeout_err);
            None
        }
    }
}

/// Load the session from KV, update its state to ProofOk, and write it back.
async fn update_session_state(env: &worker::Env, session_id: &str) -> Result<(), String> {
    let mut session = get_session_kv(env, session_id)
        .await
        .map_err(|e| format!("Failed to load session: {}", e))?
        .ok_or_else(|| format!("Session {} not found in KV", session_id))?;

    // Only transition from Pending to ProofOk. If the session is already
    // in ProofOk, Verified, Expired, or Revoked, skip the update.
    if session.state != SessionState::Pending {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[notify] Session {} already in state {:?}, skipping update",
            session_id.get(..8).unwrap_or(session_id),
            session.state
        );
        return Ok(());
    }

    session.state = SessionState::ProofOk;

    // Pass prior state (Pending, guarded above) to avoid redundant KV GET.
    update_session_kv_checked(env, &session, Some(SessionState::Pending))
        .await
        .map_err(|e| format!("Failed to update session in KV: {}", e))?;

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[notify] Session {} updated to ProofOk",
        session_id.get(..8).unwrap_or(session_id)
    );
    Ok(())
}

/// Forward the proof-verified notification to the HOSTED_CHALLENGE_NOTIFY_DO
/// Durable Object so connected WebSocket clients receive the update.
async fn push_ws_notification(env: &worker::Env, session_id: &str) -> Result<(), String> {
    let namespace = env
        .durable_object("HOSTED_CHALLENGE_NOTIFY_DO")
        .map_err(|e| format!("HOSTED_CHALLENGE_NOTIFY_DO binding unavailable: {:?}", e))?;

    let stub = namespace
        .id_from_name(session_id)
        .map_err(|e| format!("Failed to create DO id: {:?}", e))?
        .get_stub()
        .map_err(|e| format!("Failed to get DO stub: {:?}", e))?;

    let body = serde_json::json!({
        "state": "proof_ok_waiting_for_redeem"
    });

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post);

    let headers = worker::Headers::new();
    let _ = headers.set("Content-Type", "application/json");
    init.with_headers(headers);
    init.with_body(Some(worker::wasm_bindgen::JsValue::from_str(
        &body.to_string(),
    )));

    let request = worker::Request::new_with_init("https://challenge-notify-do/notify", &init)
        .map_err(|e| format!("Failed to build DO request: {:?}", e))?;

    // Per-operation timeout for ChallengeNotifyDO fetch.
    match crate::utils::timeout::with_timeout(
        "notify ChallengeNotifyDO fetch",
        crate::utils::timeout::DO_FETCH_TIMEOUT_MS,
        stub.fetch_with_request(request),
    )
    .await
    {
        Ok(Ok(_resp)) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[notify] HOSTED_CHALLENGE_NOTIFY_DO returned {}",
                _resp.status_code()
            );
            Ok(())
        }
        Ok(Err(e)) => Err(format!("DO fetch failed: {:?}", e)),
        Err(timeout_err) => Err(format!("DO fetch timed out: {}", timeout_err)),
    }
}

/// Transition the session to Expired in KV (proof failed / age_not_met).
async fn update_session_state_expired(env: &worker::Env, session_id: &str) -> Result<(), String> {
    let mut session = get_session_kv(env, session_id)
        .await
        .map_err(|e| format!("Failed to load session: {}", e))?
        .ok_or_else(|| format!("Session {} not found in KV", session_id))?;

    // Only transition from Pending. If already in a terminal state, skip.
    if session.state != SessionState::Pending {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[notify] Session {} already in state {:?}, skipping Expired update",
            session_id.get(..8).unwrap_or(session_id),
            session.state
        );
        return Ok(());
    }

    session.state = SessionState::Expired;

    // Pass prior state (Pending, guarded above) to avoid redundant KV GET.
    update_session_kv_checked(env, &session, Some(SessionState::Pending))
        .await
        .map_err(|e| format!("Failed to update session in KV: {}", e))?;

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[notify] Session {} updated to Expired",
        session_id.get(..8).unwrap_or(session_id)
    );
    Ok(())
}

/// Forward a proof-failed notification to the HOSTED_CHALLENGE_NOTIFY_DO
/// Durable Object so connected WebSocket clients receive the "expired" state.
async fn push_ws_notification_expired(env: &worker::Env, session_id: &str) -> Result<(), String> {
    let namespace = env
        .durable_object("HOSTED_CHALLENGE_NOTIFY_DO")
        .map_err(|e| format!("HOSTED_CHALLENGE_NOTIFY_DO binding unavailable: {:?}", e))?;

    let stub = namespace
        .id_from_name(session_id)
        .map_err(|e| format!("Failed to create DO id: {:?}", e))?
        .get_stub()
        .map_err(|e| format!("Failed to get DO stub: {:?}", e))?;

    let body = serde_json::json!({
        "state": "expired"
    });

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post);

    let headers = worker::Headers::new();
    let _ = headers.set("Content-Type", "application/json");
    init.with_headers(headers);
    init.with_body(Some(worker::wasm_bindgen::JsValue::from_str(
        &body.to_string(),
    )));

    let request = worker::Request::new_with_init("https://challenge-notify-do/notify", &init)
        .map_err(|e| format!("Failed to build DO request: {:?}", e))?;

    // Per-operation timeout for ChallengeNotifyDO fetch (expired path).
    match crate::utils::timeout::with_timeout(
        "notify ChallengeNotifyDO fetch (expired)",
        crate::utils::timeout::DO_FETCH_TIMEOUT_MS,
        stub.fetch_with_request(request),
    )
    .await
    {
        Ok(Ok(_resp)) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[notify] HOSTED_CHALLENGE_NOTIFY_DO (expired) returned {}",
                _resp.status_code()
            );
            Ok(())
        }
        Ok(Err(e)) => Err(format!("DO fetch (expired) failed: {:?}", e)),
        Err(timeout_err) => Err(format!("DO fetch (expired) timed out: {}", timeout_err)),
    }
}

// ============================================================================
// Tests
// ============================================================================
//
// The notify functions themselves require a wasm32 worker::Env and cannot be
// called directly in native tests. Instead we validate the state machine
// invariants that `update_session_state` and `update_session_state_expired`
// depend on, and the ChallengeNotifyDO state constants that govern which
// WebSocket messages are classified as success or failure.

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use crate::hosted::types::session::SessionState;

    // ========================================================================
    // SessionState transition invariants used by update_session_state
    // ========================================================================

    #[test]
    fn notify_proof_verified_requires_pending_state() {
        // update_session_state only transitions Pending -> ProofOk.
        // All other source states must be rejected.
        assert!(
            SessionState::Pending.is_valid_transition(SessionState::ProofOk),
            "Pending -> ProofOk must be a valid transition"
        );
        assert!(
            !SessionState::ProofOk.is_valid_transition(SessionState::ProofOk),
            "ProofOk -> ProofOk (self-transition) must be rejected"
        );
        assert!(
            !SessionState::Verified.is_valid_transition(SessionState::ProofOk),
            "Verified -> ProofOk must be rejected"
        );
        assert!(
            !SessionState::Expired.is_valid_transition(SessionState::ProofOk),
            "Expired -> ProofOk must be rejected"
        );
        assert!(
            !SessionState::Revoked.is_valid_transition(SessionState::ProofOk),
            "Revoked -> ProofOk must be rejected"
        );
    }

    #[test]
    fn notify_proof_failed_requires_pending_state() {
        // update_session_state_expired only transitions Pending -> Expired.
        assert!(
            SessionState::Pending.is_valid_transition(SessionState::Expired),
            "Pending -> Expired must be a valid transition"
        );
        assert!(
            SessionState::ProofOk.is_valid_transition(SessionState::Expired),
            "ProofOk -> Expired is a valid transition (used by expiry, not this path)"
        );
    }

    #[test]
    fn terminal_states_reject_proof_ok_and_expired() {
        let terminal = [
            SessionState::Verified,
            SessionState::Expired,
            SessionState::Revoked,
        ];
        for state in terminal {
            assert!(
                !state.is_valid_transition(SessionState::ProofOk),
                "{:?} -> ProofOk must be rejected",
                state
            );
            assert!(
                !state.is_valid_transition(SessionState::Expired),
                "{:?} -> Expired must be rejected",
                state
            );
        }
    }

    // ========================================================================
    // ChallengeNotifyDO state classification
    // ========================================================================

    /// The ChallengeNotifyDO SUCCESS_STATES and FAILURE_STATES constants
    /// (tested in challenge_notify_do.rs) define the set of valid WebSocket
    /// notification payloads. These tests verify that the states pushed by
    /// notify_proof_verified and notify_proof_failed are within those sets.

    #[test]
    fn proof_ok_state_matches_do_success_state() {
        // notify_proof_verified pushes {"state": "proof_ok_waiting_for_redeem"}
        // which must be in ChallengeNotifyDO::SUCCESS_STATES.
        let serialised =
            serde_json::to_string(&SessionState::ProofOk).expect("ProofOk must serialise");
        // The serde rename produces "proof_ok_waiting_for_redeem" (with quotes)
        assert_eq!(
            serialised, "\"proof_ok_waiting_for_redeem\"",
            "ProofOk must serialise to the DO success state value"
        );
    }

    #[test]
    fn expired_state_matches_do_failure_state() {
        // notify_proof_failed pushes {"state": "expired"}
        // which must be in ChallengeNotifyDO::FAILURE_STATES.
        let serialised =
            serde_json::to_string(&SessionState::Expired).expect("Expired must serialise");
        assert_eq!(
            serialised, "\"expired\"",
            "Expired must serialise to the DO failure state value"
        );
    }

    // ========================================================================
    // SessionState serde edge cases relevant to notify path
    // ========================================================================

    #[test]
    fn unknown_state_string_rejected_by_serde() {
        // If KV contains a session with an unrecognised state string, serde
        // must reject it so the notify path does not operate on garbage.
        let bogus_states = ["\"unknown\"", "\"proof_ok\"", "\"\"", "\"PENDING\""];
        for json in bogus_states {
            let result = serde_json::from_str::<SessionState>(json);
            assert!(
                result.is_err(),
                "State {} must be rejected by SessionState serde",
                json
            );
        }
    }

    #[test]
    fn null_state_rejected_by_serde() {
        let result = serde_json::from_str::<SessionState>("null");
        assert!(result.is_err(), "null must be rejected");
    }

    #[test]
    fn numeric_state_rejected_by_serde() {
        let result = serde_json::from_str::<SessionState>("42");
        assert!(result.is_err(), "numeric values must be rejected");
    }

    // ========================================================================
    // KV key format used by lookup_session_for_challenge
    // ========================================================================

    #[test]
    fn challenge_to_session_key_format() {
        let challenge_id = "chall-abc-123";
        let key = format!("challenge_to_session:{}", challenge_id);
        assert_eq!(key, "challenge_to_session:chall-abc-123");
        assert!(key.starts_with("challenge_to_session:"));
    }

    #[test]
    fn challenge_to_session_key_with_empty_id() {
        let key = format!("challenge_to_session:{}", "");
        assert_eq!(key, "challenge_to_session:");
    }

    #[test]
    fn challenge_to_session_key_with_special_chars() {
        let challenge_id = "chall/with spaces&special<chars>";
        let key = format!("challenge_to_session:{}", challenge_id);
        assert!(key.starts_with("challenge_to_session:"));
        assert!(key.contains(challenge_id));
    }

    // ========================================================================
    // WebSocket push payload format
    // ========================================================================

    #[test]
    fn ws_notify_payload_success_format() {
        // The push_ws_notification function sends this JSON to the DO.
        let body = serde_json::json!({
            "state": "proof_ok_waiting_for_redeem"
        });
        let state = body.get("state").and_then(|v| v.as_str());
        assert_eq!(state, Some("proof_ok_waiting_for_redeem"));
    }

    #[test]
    fn ws_notify_payload_expired_format() {
        // The push_ws_notification_expired function sends this JSON to the DO.
        let body = serde_json::json!({
            "state": "expired"
        });
        let state = body.get("state").and_then(|v| v.as_str());
        assert_eq!(state, Some("expired"));
    }

    #[test]
    fn ws_notify_payload_missing_state_detected() {
        // Ensures the pattern used to detect missing "state" works.
        let body = serde_json::json!({});
        let state = body.get("state").and_then(|v| v.as_str());
        assert!(state.is_none(), "Missing state must be detected");
    }

    #[test]
    fn ws_notify_payload_null_state_detected() {
        let body = serde_json::json!({ "state": null });
        let state = body.get("state").and_then(|v| v.as_str());
        assert!(state.is_none(), "null state must be detected");
    }
}
