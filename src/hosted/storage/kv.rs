// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! KV-based storage for sessions and nonces.
//!
//! This module provides fast KV-based storage that eliminates Durable Object
//! cold start latency (100-300ms per DO call). KV operations typically complete
//! in 10-50ms, providing ~5-10x faster storage access.
//!
//! # Security
//!
//! - Sessions are encrypted with AES-256-GCM using the MEK before storage
//! - Nonces use KV TTL for automatic expiration (no encryption needed - just presence check)
//! - All sensitive data is encrypted at rest
#![forbid(unsafe_code)]

use crate::hosted::durable_objects::sharding::get_shard_name;
use crate::hosted::durable_objects::HostedNonceDOAuditEvent;
use crate::hosted::encryption::{
    decrypt_with_mek, encrypt_with_mek, get_mek_from_secrets, get_mek_secondary_from_secrets,
};
use crate::hosted::types::errors::HostedApiError as ApiError;
use crate::hosted::types::session::{HostedSession, SessionState};
#[cfg(target_arch = "wasm32")]
use crate::security::log_sanitizer::redact_session_id;
use crate::security::AuditLogger;
use worker::Env;
use zeroize::Zeroizing;

/// Associated Authenticated Data for session encryption
const SESSION_AAD: &[u8] = b"provii-verifier:session:v1";

/// Store a session in KV with encryption.
///
/// The session is serialised to JSON, encrypted with AES-256-GCM using the MEK,
/// and stored in the HOSTED_SESSIONS KV namespace with TTL.
///
/// # Arguments
///
/// * `env` - Cloudflare Workers environment
/// * `session` - The session to store
/// * `ttl_seconds` - TTL for the KV entry
///
/// # Returns
///
/// Ok(()) on success, ApiError on failure
pub async fn store_session_kv(
    env: &Env,
    session: &HostedSession,
    ttl_seconds: u64,
) -> Result<(), ApiError> {
    // Get MEK for encryption (already returns Zeroizing<Vec<u8>>)
    // M1: An unavailable MEK is a transient/availability failure, not a logic
    // error, so map it to 503 (not 500). With the startup pre-load this should
    // only occur when HOSTED_MEK is unprovisioned, in which case fast 503s are
    // the correct signal rather than misleading 500s.
    let mek = get_mek_from_secrets(env).await.map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[SessionKV] Failed to get MEK: {}", _e);
        ApiError::service_unavailable("Encryption key unavailable")
    })?;

    // Serialize session to JSON. Wrapped in Zeroizing so the plaintext
    // (which contains code_verifier and other secrets) is cleared on drop.
    let session_json = Zeroizing::new(serde_json::to_string(session).map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[SessionKV] Failed to serialize session: {}", _e);
        ApiError::internal("Failed to serialize session")
    })?);

    // Encrypt the session data
    let encrypted = encrypt_with_mek(&mek, &session_json, SESSION_AAD).map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[SessionKV] Encryption failed: {}", _e);
        ApiError::internal("Failed to encrypt session")
    })?;

    // Get KV namespace
    let kv = env.kv("HOSTED_SESSIONS").map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[SessionKV] Failed to get KV namespace: {}", _e);
        ApiError::internal("Failed to access session storage")
    })?;

    // Store with TTL and per-operation timeout.
    let key = format!("session:{}", session.session_id);
    let put_builder = kv.put(&key, &encrypted).map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[SessionKV] Failed to create put builder: {}", _e);
        ApiError::internal("Failed to store session")
    })?;
    crate::utils::timeout::with_timeout(
        "session KV write",
        crate::utils::timeout::KV_WRITE_TIMEOUT_MS,
        put_builder.expiration_ttl(ttl_seconds).execute(),
    )
    .await
    .map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[SessionKV] KV put timed out: {}", _e);
        ApiError::internal("Session storage timed out")
    })?
    .map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[SessionKV] KV put failed: {}", _e);
        ApiError::internal("Failed to store session")
    })?;

    // AL-087: Structured audit for KV session write.
    // ADV-VA-026: Redact session IDs in logs to prevent exposure of bearer-like tokens.
    #[cfg(target_arch = "wasm32")]
    worker::console_log!(
        "{{\"audit\":true,\"event\":\"kv_session_write\",\"severity\":\"info\",\"operation\":\"put\",\"session_id\":\"{}\",\"ttl_seconds\":{}}}",
        redact_session_id(&session.session_id),
        ttl_seconds
    );
    Ok(())
}

/// Store challenge_id -> session_id mapping in KV for WebSocket push notifications.
///
/// When provii-verifier sends a `POST /v1/internal/notify` with a `challenge_id`,
/// this mapping finds the session's WebSocket Durable Object instance. Without
/// it, the notification is silently dropped and the client falls back to
/// polling (3-5 s delay).
///
/// This write is non-fatal: if it fails, polling still works. The caller should
/// log the failure but not abort the challenge flow.
pub async fn store_challenge_mapping_kv(
    env: &Env,
    challenge_id: &str,
    session_id: &str,
    ttl_seconds: u64,
) -> Result<(), String> {
    let kv = env
        .kv("HOSTED_SESSIONS")
        .map_err(|e| format!("KV binding error: {}", e))?;
    let key = format!("challenge_to_session:{}", challenge_id);
    // Per-operation timeout for challenge mapping KV write.
    let put_builder = kv
        .put(&key, session_id)
        .map_err(|e| format!("KV put builder error: {}", e))?;
    crate::utils::timeout::with_timeout(
        "challenge_mapping KV write",
        crate::utils::timeout::KV_WRITE_TIMEOUT_MS,
        put_builder.expiration_ttl(ttl_seconds).execute(),
    )
    .await
    .map_err(|e| format!("KV put timed out: {}", e))?
    .map_err(|e| format!("KV put execute error: {}", e))?;

    // ADV-VA-026: Redact session IDs in logs.
    #[cfg(target_arch = "wasm32")]
    worker::console_log!(
        "{{\"audit\":true,\"event\":\"kv_challenge_mapping_write\",\"severity\":\"info\",\"operation\":\"put\",\"challenge_id\":\"{}\",\"session_id\":\"{}\",\"ttl_seconds\":{}}}",
        challenge_id,
        redact_session_id(session_id),
        ttl_seconds
    );
    Ok(())
}

/// Retrieve a session from KV and decrypt it.
///
/// # Arguments
///
/// * `env` - Cloudflare Workers environment
/// * `session_id` - The session ID to retrieve
///
/// # Returns
///
/// The decrypted session on success, None if not found, ApiError on failure
pub async fn get_session_kv(
    env: &Env,
    session_id: &str,
) -> Result<Option<HostedSession>, ApiError> {
    get_session_kv_tracked(env, session_id, None).await
}

/// Variant of [`get_session_kv`] that records which HOSTED_MEK slot satisfied
/// the session decrypt path via `slot_out`. Callers wire this slot
/// signal into a [`crate::security::secret_versions::SecretVersionLine`] so the
/// per-request log line and the `x-secret-version` response header carry the
/// satisfying-slot fingerprint. The outparam is left untouched on
/// session-not-found and on decrypt failure.
pub async fn get_session_kv_tracked(
    env: &Env,
    session_id: &str,
    slot_out: Option<&mut Option<crate::security::secret_versions::RotationSlot>>,
) -> Result<Option<HostedSession>, ApiError> {
    use crate::security::secret_versions::RotationSlot;

    // Get KV namespace
    let kv = env.kv("HOSTED_SESSIONS").map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[SessionKV] Failed to get KV namespace: {}", _e);
        ApiError::internal("Failed to access session storage")
    })?;

    // Get encrypted session with per-operation timeout.
    let key = format!("session:{}", session_id);
    let kv_clone = kv.clone();
    let key_clone = key.clone();
    let encrypted = match crate::utils::timeout::with_timeout(
        "session KV read",
        crate::utils::timeout::KV_READ_TIMEOUT_MS,
        async move { kv_clone.get(&key_clone).text().await },
    )
    .await
    {
        Ok(Ok(Some(data))) => data,
        Ok(Ok(None)) => {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "[SessionKV] Session not found: {}",
                redact_session_id(session_id)
            );
            return Ok(None);
        }
        Ok(Err(_e)) => {
            #[cfg(target_arch = "wasm32")]
            worker::console_error!("[SessionKV] KV get failed: {}", _e);
            return Err(ApiError::internal("Failed to retrieve session"));
        }
        Err(_timeout_err) => {
            #[cfg(target_arch = "wasm32")]
            worker::console_error!("[SessionKV] KV get timed out: {}", _timeout_err);
            return Err(ApiError::internal("Session retrieval timed out"));
        }
    };

    // Get MEK for decryption (already returns Zeroizing<Vec<u8>>)
    // M1: 503 (not 500) on an unavailable MEK; see store_session_kv above.
    let mek = get_mek_from_secrets(env).await.map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[SessionKV] Failed to get MEK: {}", _e);
        ApiError::service_unavailable("Encryption key unavailable")
    })?;

    // Decrypt session data with primary MEK, falling back to secondary MEK
    // during key rotation. SC-009: Secondary MEK is now cached at process level.
    let (session_json, slot_used) = match decrypt_with_mek(&mek, &encrypted, SESSION_AAD) {
        Ok(json) => (json, RotationSlot::Current),
        Err(_primary_err) => {
            // SECURITY: Key rotation fallback. Try secondary MEK for sessions
            // encrypted before the most recent rotation.
            let secondary_mek = get_mek_secondary_from_secrets(env).await;

            match secondary_mek {
                Some(sec_mek) => {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "{{\"audit\":true,\"event\":\"kv_session_mek_fallback\",\"severity\":\"warning\",\"session_id\":\"{}\",\"message\":\"Primary MEK failed, trying secondary\"}}",
                        redact_session_id(session_id)
                    );

                    let plaintext =
                        decrypt_with_mek(&sec_mek, &encrypted, SESSION_AAD).map_err(|_| {
                            #[cfg(target_arch = "wasm32")]
                            worker::console_error!(
                                "[SessionKV] Both primary and secondary MEK failed for session: {}",
                                redact_session_id(session_id)
                            );
                            ApiError::internal("Failed to decrypt session")
                        })?;
                    (plaintext, RotationSlot::Previous)
                }
                None => {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_error!(
                        "[SessionKV] Primary MEK decryption failed and no secondary MEK available"
                    );
                    return Err(ApiError::internal("Failed to decrypt session"));
                }
            }
        }
    };
    if let Some(out) = slot_out {
        *out = Some(slot_used);
    }

    // Deserialize session
    let session: HostedSession = serde_json::from_str(&session_json).map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[SessionKV] Failed to deserialize session: {}", _e);
        ApiError::internal("Failed to parse session")
    })?;

    #[cfg(target_arch = "wasm32")]
    worker::console_log!(
        "[SessionKV] Session retrieved: {}",
        redact_session_id(session_id)
    );
    Ok(Some(session))
}

/// Validate a session state transition from an optional prior state.
///
/// ADV-VA-024: Enforces the state machine transition DAG. If `prior` is
/// `None`, the check is skipped (first write or caller opts out). If `prior`
/// is `Some`, the transition must be valid according to
/// `SessionState::is_valid_transition`, or the states must be equal (no-op
/// update such as incrementing a counter without changing state).
///
/// This is a pure function extracted for unit testing.
pub(crate) fn validate_transition(
    prior: Option<SessionState>,
    new: SessionState,
) -> Result<(), ApiError> {
    if let Some(prior_state) = prior {
        if prior_state != new && !prior_state.is_valid_transition(new) {
            #[cfg(target_arch = "wasm32")]
            worker::console_error!(
                "[SessionKV] ADV-VA-024: Invalid state transition {:?} -> {:?}",
                prior_state,
                new
            );
            return Err(ApiError::internal(format!(
                "Invalid session state transition from {:?} to {:?}",
                prior_state, new
            )));
        }
    }
    Ok(())
}

/// Update a session in KV with caller-supplied prior state for transition
/// validation.
///
/// SECURITY: Uses the remaining TTL derived from `session.expires_at` rather
/// than the full session lifetime. This prevents an update from extending a
/// session beyond its original expiration time (WI-14b). A floor of 60 s is
/// applied to avoid immediate KV expiry on near-expiration sessions.
///
/// ADV-VA-024: Validates the state machine transition using `prior_state`
/// supplied by the caller (who already holds the decrypted session), avoiding
/// a redundant KV GET + AES-256-GCM decrypt cycle.
///
/// INV-VA-048: TOCTOU is not a concern here. KV is eventually consistent and
/// the DO nonce store serialises authoritative state transitions. The KV
/// write is a cache update, not the source of truth.
///
/// # Arguments
///
/// * `env` - Cloudflare Workers environment
/// * `session` - The updated session to write
/// * `prior_state` - The session state before this update (as held by the
///   caller). Pass `None` to skip transition validation (e.g. first write).
pub async fn update_session_kv_checked(
    env: &Env,
    session: &HostedSession,
    prior_state: Option<SessionState>,
) -> Result<(), ApiError> {
    validate_transition(prior_state, session.state)?;

    let now = crate::utils::current_timestamp();
    let remaining = session.expires_at.saturating_sub(now).max(60);
    store_session_kv(env, session, remaining).await
}

/// Atomically check-and-set a nonce via the NonceDO Durable Object.
///
/// Provides true atomicity via the single-writer guarantee of Durable
/// Objects. KV's eventual consistency allows a TOCTOU race window where
/// two concurrent requests with the same nonce can both succeed. The DO
/// eliminates this window entirely.
///
/// Nonces are sharded across 25 DO instances using consistent hashing to
/// distribute load.
///
/// # Arguments
///
/// * `env` - Cloudflare Workers environment
/// * `nonce` - The nonce to store
/// * `ttl_seconds` - TTL for the nonce
///
/// # Returns
///
/// Ok(true) if nonce was newly stored, Ok(false) if already exists (replay detected)
///
/// AL-008: When `audit_logger` is provided, audit events embedded in the DO
/// response body (`nonce_replay_detected` is the most important) are dispatched
/// via the audit queue. Callers in production must always pass `Some(...)` so
/// CRITICAL replay events reach D1.
pub async fn store_nonce_do(
    env: &Env,
    nonce: &str,
    ttl_seconds: u64,
    audit_logger: Option<&AuditLogger>,
    client_ip: &str,
    origin: &str,
    request_id: &str,
) -> Result<bool, ApiError> {
    if nonce.is_empty() {
        return Err(ApiError::invalid_request("Nonce cannot be empty"));
    }

    const NONCE_SHARD_COUNT: usize = 25;

    let namespace = env.durable_object("HOSTED_NONCE_DO").map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[NonceDO] Failed to get DO namespace: {}", _e);
        ApiError::internal("Failed to access nonce storage")
    })?;

    let shard_name = get_shard_name("nonce", nonce, NONCE_SHARD_COUNT);

    let id = namespace.id_from_name(&shard_name).map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!(
            "[NonceDO] Failed to get ID for shard {}: {}",
            shard_name,
            _e
        );
        ApiError::internal("Failed to access nonce storage")
    })?;

    let stub = id.get_stub().map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[NonceDO] Failed to get stub: {}", _e);
        ApiError::internal("Failed to access nonce storage")
    })?;

    // Build POST /check-and-set request with nonce and TTL
    let body = serde_json::json!({
        "nonce": nonce,
        "ttl_seconds": ttl_seconds
    });

    let body_str = serde_json::to_string(&body)
        .map_err(|e| ApiError::internal(format!("Failed to serialize nonce request: {}", e)))?;

    let headers = worker::Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| ApiError::internal(format!("Failed to set header: {}", e)))?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(body_str.into()));

    let do_request = worker::Request::new_with_init("https://nonce-do/check-and-set", &init)
        .map_err(|e| ApiError::internal(format!("Failed to create DO request: {}", e)))?;

    // Per-operation timeout for hosted NonceDO fetch.
    let mut response = crate::utils::timeout::with_timeout(
        "hosted NonceDO fetch",
        crate::utils::timeout::DO_FETCH_TIMEOUT_MS,
        stub.fetch_with_request(do_request),
    )
    .await
    .map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!(
            "[NonceDO] DO request timed out for shard {}: {}",
            shard_name,
            _e
        );
        ApiError::internal("Nonce check timed out")
    })?
    .map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!(
            "[NonceDO] DO request failed for shard {}: {}",
            shard_name,
            _e
        );
        ApiError::internal("Failed to check nonce")
    })?;

    match response.status_code() {
        200 => {
            // Nonce stored successfully (first use). The 200 body carries an
            // empty `audit_events` array today; still drain and inspect to
            // future-proof against new event types from the DO.
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "[NonceDO] Nonce stored in shard {} (TTL: {}s)",
                shard_name,
                ttl_seconds
            );
            let body = response.text().await.unwrap_or_default();
            dispatch_hosted_nonce_events(audit_logger, &body, client_ip, origin, request_id).await;
            Ok(true)
        }
        409 => {
            // Nonce already exists (replay detected). The 409 body carries a
            // CRITICAL `nonce_replay_detected` event that must reach D1.
            #[cfg(target_arch = "wasm32")]
            worker::console_error!(
                "[NonceDO] Replay detected in shard {}: {}",
                shard_name,
                nonce.get(..16).unwrap_or(nonce)
            );
            let body = response.text().await.unwrap_or_default();
            dispatch_hosted_nonce_events(audit_logger, &body, client_ip, origin, request_id).await;
            Ok(false)
        }
        _status => {
            let _error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            #[cfg(target_arch = "wasm32")]
            worker::console_error!(
                "[NonceDO] Unexpected status {} from shard {}: {}",
                _status,
                shard_name,
                _error_text
            );
            Err(ApiError::internal("Failed to check nonce"))
        }
    }
}

/// AL-008: Best-effort dispatch of the `audit_events` array embedded in a
/// `HostedNonceDO` response body. Failures (missing logger, malformed JSON,
/// unknown event shape) are logged at debug level and do not propagate.
async fn dispatch_hosted_nonce_events(
    audit_logger: Option<&AuditLogger>,
    body: &str,
    client_ip: &str,
    origin: &str,
    request_id: &str,
) {
    let Some(logger) = audit_logger else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return;
    };
    let Some(array) = value.get("audit_events").and_then(|v| v.as_array()) else {
        return;
    };
    if array.is_empty() {
        return;
    }
    let events: Vec<HostedNonceDOAuditEvent> = array
        .iter()
        .filter_map(|v| serde_json::from_value::<HostedNonceDOAuditEvent>(v.clone()).ok())
        .collect();
    if events.is_empty() {
        return;
    }
    logger
        .dispatch_hosted_nonce_audit_events(&events, client_ip, origin, request_id)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::log_sanitizer::redact_session_id;

    // Compile-time check: SESSION_AAD must not be empty.
    const _: () = assert!(!SESSION_AAD.is_empty());

    #[test]
    fn test_session_aad_is_set() {
        assert!(SESSION_AAD.starts_with(b"provii-verifier"));
    }

    #[test]
    fn test_shard_name_format() {
        let name = get_shard_name("nonce", "test-key", 25);
        assert!(name.starts_with("nonce-shard-"));
    }

    #[test]
    fn test_shard_name_deterministic() {
        let name1 = get_shard_name("nonce", "test-key", 25);
        let name2 = get_shard_name("nonce", "test-key", 25);
        assert_eq!(name1, name2);
    }

    #[test]
    fn test_shard_name_within_range() -> Result<(), Box<dyn std::error::Error>> {
        let shard_count = 25;
        for i in 0..100 {
            let key = format!("test-key-{}", i);
            let name = get_shard_name("nonce", &key, shard_count);
            let shard_num: usize = name
                .strip_prefix("nonce-shard-")
                .ok_or("missing prefix")?
                .parse()?;
            assert!(shard_num < shard_count);
        }
        Ok(())
    }

    // ── validate_transition tests ─────────────────────────────────────────

    #[test]
    fn test_validate_transition_pending_to_proof_ok_passes() {
        assert!(validate_transition(Some(SessionState::Pending), SessionState::ProofOk).is_ok());
    }

    #[test]
    fn test_validate_transition_pending_to_verified_fails() {
        assert!(validate_transition(Some(SessionState::Pending), SessionState::Verified).is_err());
    }

    #[test]
    fn test_validate_transition_none_to_any_passes() {
        // None prior state skips the check entirely.
        assert!(validate_transition(None, SessionState::Pending).is_ok());
        assert!(validate_transition(None, SessionState::ProofOk).is_ok());
        assert!(validate_transition(None, SessionState::Verified).is_ok());
        assert!(validate_transition(None, SessionState::Expired).is_ok());
        assert!(validate_transition(None, SessionState::Revoked).is_ok());
    }

    #[test]
    fn test_validate_transition_same_to_same_passes() {
        // Same-state updates (e.g. counter increment without state change) must pass.
        assert!(validate_transition(Some(SessionState::Pending), SessionState::Pending).is_ok());
        assert!(validate_transition(Some(SessionState::ProofOk), SessionState::ProofOk).is_ok());
        assert!(validate_transition(Some(SessionState::Verified), SessionState::Verified).is_ok());
    }

    #[test]
    fn test_validate_transition_proof_ok_to_verified_passes() {
        assert!(validate_transition(Some(SessionState::ProofOk), SessionState::Verified).is_ok());
    }

    #[test]
    fn test_validate_transition_proof_ok_to_expired_passes() {
        assert!(validate_transition(Some(SessionState::ProofOk), SessionState::Expired).is_ok());
    }

    #[test]
    fn test_validate_transition_verified_to_pending_fails() {
        assert!(validate_transition(Some(SessionState::Verified), SessionState::Pending).is_err());
    }

    #[test]
    fn test_validate_transition_expired_to_pending_fails() {
        assert!(validate_transition(Some(SessionState::Expired), SessionState::Pending).is_err());
    }

    // ── validate_transition: complete transition matrix ──────────────

    #[test]
    fn test_validate_transition_pending_to_expired_passes() {
        assert!(validate_transition(Some(SessionState::Pending), SessionState::Expired).is_ok());
    }

    #[test]
    fn test_validate_transition_pending_to_revoked_passes() {
        assert!(validate_transition(Some(SessionState::Pending), SessionState::Revoked).is_ok());
    }

    #[test]
    fn test_validate_transition_proof_ok_to_revoked_passes() {
        assert!(validate_transition(Some(SessionState::ProofOk), SessionState::Revoked).is_ok());
    }

    #[test]
    fn test_validate_transition_proof_ok_to_pending_fails() {
        assert!(validate_transition(Some(SessionState::ProofOk), SessionState::Pending).is_err());
    }

    #[test]
    fn test_validate_transition_verified_to_expired_fails() {
        assert!(validate_transition(Some(SessionState::Verified), SessionState::Expired).is_err());
    }

    #[test]
    fn test_validate_transition_verified_to_revoked_fails() {
        assert!(validate_transition(Some(SessionState::Verified), SessionState::Revoked).is_err());
    }

    #[test]
    fn test_validate_transition_expired_to_verified_fails() {
        assert!(validate_transition(Some(SessionState::Expired), SessionState::Verified).is_err());
    }

    #[test]
    fn test_validate_transition_expired_to_revoked_fails() {
        assert!(validate_transition(Some(SessionState::Expired), SessionState::Revoked).is_err());
    }

    #[test]
    fn test_validate_transition_revoked_to_pending_fails() {
        assert!(validate_transition(Some(SessionState::Revoked), SessionState::Pending).is_err());
    }

    #[test]
    fn test_validate_transition_revoked_to_proof_ok_fails() {
        assert!(validate_transition(Some(SessionState::Revoked), SessionState::ProofOk).is_err());
    }

    #[test]
    fn test_validate_transition_revoked_to_verified_fails() {
        assert!(validate_transition(Some(SessionState::Revoked), SessionState::Verified).is_err());
    }

    #[test]
    fn test_validate_transition_revoked_to_expired_fails() {
        assert!(validate_transition(Some(SessionState::Revoked), SessionState::Expired).is_err());
    }

    #[test]
    fn test_validate_transition_expired_to_expired_passes() {
        // Same-state update is allowed
        assert!(validate_transition(Some(SessionState::Expired), SessionState::Expired).is_ok());
    }

    #[test]
    fn test_validate_transition_revoked_to_revoked_passes() {
        assert!(validate_transition(Some(SessionState::Revoked), SessionState::Revoked).is_ok());
    }

    // ── get_shard_name: additional edge cases ────────────────────────

    #[test]
    fn test_shard_name_different_prefixes() {
        let s1 = get_shard_name("nonce", "key1", 25);
        let s2 = get_shard_name("session", "key1", 25);
        // Different prefixes produce different shard names even for same key
        assert!(s1.starts_with("nonce-shard-"));
        assert!(s2.starts_with("session-shard-"));
    }

    #[test]
    fn test_shard_name_single_shard() {
        // With shard_count=1, everything goes to shard-0
        let name = get_shard_name("nonce", "any-key", 1);
        assert_eq!(name, "nonce-shard-0");
    }

    #[test]
    fn test_shard_name_zero_shard_count() {
        // shard_count=0 should not panic (max(1) applied)
        let name = get_shard_name("nonce", "any-key", 0);
        assert_eq!(name, "nonce-shard-0");
    }

    #[test]
    fn test_shard_name_large_shard_count() {
        let shard_count = 1000;
        for i in 0..50 {
            let key = format!("key-{}", i);
            let name = get_shard_name("nonce", &key, shard_count);
            let shard_num: usize = name.strip_prefix("nonce-shard-").unwrap().parse().unwrap();
            assert!(shard_num < shard_count);
        }
    }

    #[test]
    fn test_shard_name_empty_key() {
        let name = get_shard_name("nonce", "", 25);
        assert!(name.starts_with("nonce-shard-"));
    }

    #[test]
    fn test_shard_name_empty_prefix() {
        let name = get_shard_name("", "key", 25);
        assert!(name.starts_with("-shard-"));
    }

    // ── SESSION_AAD constant ─────────────────────────────────────────

    #[test]
    fn test_session_aad_has_version_suffix() {
        let aad_str = std::str::from_utf8(SESSION_AAD).unwrap();
        assert!(aad_str.ends_with(":v1"));
    }

    #[test]
    fn test_session_aad_contains_context() {
        let aad_str = std::str::from_utf8(SESSION_AAD).unwrap();
        assert!(aad_str.contains("session"));
    }

    // ── SESSION_AAD: exact value regression ─────────────────────────────

    #[test]
    fn test_session_aad_exact_value() {
        assert_eq!(SESSION_AAD, b"provii-verifier:session:v1");
    }

    #[test]
    fn test_session_aad_is_valid_utf8() -> Result<(), Box<dyn std::error::Error>> {
        let _ = std::str::from_utf8(SESSION_AAD)?;
        Ok(())
    }

    #[test]
    fn test_session_aad_has_three_colon_separated_parts() -> Result<(), Box<dyn std::error::Error>>
    {
        let aad_str = std::str::from_utf8(SESSION_AAD)?;
        let parts: Vec<&str> = aad_str.split(':').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "provii-verifier");
        assert_eq!(parts[1], "session");
        assert_eq!(parts[2], "v1");
        Ok(())
    }

    // ── get_shard_name: unicode / special character keys ────────────────

    #[test]
    fn test_shard_name_unicode_key() -> Result<(), Box<dyn std::error::Error>> {
        let name = get_shard_name("nonce", "\u{1F600}\u{1F4A9}", 25);
        assert!(name.starts_with("nonce-shard-"));
        let shard_num: usize = name
            .strip_prefix("nonce-shard-")
            .ok_or("prefix missing")?
            .parse()?;
        assert!(shard_num < 25);
        Ok(())
    }

    #[test]
    fn test_shard_name_unicode_prefix() {
        let name = get_shard_name("\u{00E9}\u{00E8}", "key", 10);
        assert!(name.contains("-shard-"));
    }

    #[test]
    fn test_shard_name_very_long_key() -> Result<(), Box<dyn std::error::Error>> {
        let long_key: String = "a".repeat(10_000);
        let name = get_shard_name("nonce", &long_key, 25);
        assert!(name.starts_with("nonce-shard-"));
        let shard_num: usize = name
            .strip_prefix("nonce-shard-")
            .ok_or("prefix missing")?
            .parse()?;
        assert!(shard_num < 25);
        Ok(())
    }

    #[test]
    fn test_shard_name_special_characters_in_key() {
        for key in &[
            "key\nwith\nnewlines",
            "key\twith\ttabs",
            "key with spaces",
            "key/with/slashes",
        ] {
            let name = get_shard_name("nonce", key, 25);
            assert!(name.starts_with("nonce-shard-"));
        }
    }

    #[test]
    fn test_shard_name_different_keys_can_produce_different_shards() {
        // With 25 shards and many keys, we should see at least two distinct shards
        let mut seen = std::collections::HashSet::new();
        for i in 0..200 {
            let key = format!("test-key-{}", i);
            let name = get_shard_name("nonce", &key, 25);
            seen.insert(name);
        }
        // With 200 keys over 25 shards, all shards should be hit (extremely high probability)
        assert!(seen.len() > 1, "all keys landed in the same shard");
    }

    #[test]
    fn test_shard_name_distribution_quality() -> Result<(), Box<dyn std::error::Error>> {
        // Verify rough uniformity: no shard should get more than 2x its fair share
        let shard_count = 25usize;
        let total_keys = 2500usize;
        let mut counts = vec![0usize; shard_count];
        for i in 0..total_keys {
            let key = format!("distribution-test-{}", i);
            let name = get_shard_name("nonce", &key, shard_count);
            let shard_num: usize = name
                .strip_prefix("nonce-shard-")
                .ok_or("prefix missing")?
                .parse()?;
            counts[shard_num] += 1;
        }
        let expected = total_keys / shard_count; // 100
        for (shard_idx, &count) in counts.iter().enumerate() {
            assert!(
                count > 0,
                "shard {} received zero keys out of {}",
                shard_idx,
                total_keys
            );
            assert!(
                count < expected * 3,
                "shard {} received {} keys, expected ~{} (3x threshold)",
                shard_idx,
                count,
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn test_shard_name_shard_count_two() {
        // Binary sharding: every key must produce shard-0 or shard-1
        for i in 0..50 {
            let key = format!("binary-key-{}", i);
            let name = get_shard_name("pfx", &key, 2);
            assert!(name == "pfx-shard-0" || name == "pfx-shard-1");
        }
    }

    #[test]
    fn test_shard_name_max_shard_count() {
        // usize::MAX should not panic (u64 conversion may saturate)
        let name = get_shard_name("nonce", "key", usize::MAX);
        assert!(name.starts_with("nonce-shard-"));
    }

    // ── KV key format patterns ──────────────────────────────────────────
    //
    // These test the key format strings used in store_session_kv,
    // get_session_kv, and store_challenge_mapping_kv. The format logic
    // is inlined in async functions that need Env, so we replicate the
    // exact format expressions here for regression coverage.

    #[test]
    fn test_session_kv_key_format() {
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let key = format!("session:{}", session_id);
        assert_eq!(key, "session:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_session_kv_key_format_empty_id() {
        let key = format!("session:{}", "");
        assert_eq!(key, "session:");
    }

    #[test]
    fn test_challenge_mapping_kv_key_format() {
        let challenge_id = "chal-abc-123";
        let key = format!("challenge_to_session:{}", challenge_id);
        assert_eq!(key, "challenge_to_session:chal-abc-123");
    }

    #[test]
    fn test_challenge_mapping_kv_key_format_empty_id() {
        let key = format!("challenge_to_session:{}", "");
        assert_eq!(key, "challenge_to_session:");
    }

    // ── validate_transition: error type and message content ─────────────

    #[test]
    fn test_validate_transition_error_is_internal() -> Result<(), Box<dyn std::error::Error>> {
        let result = validate_transition(Some(SessionState::Verified), SessionState::Pending);
        let err = result.err().ok_or("expected Err, got Ok")?;
        assert_eq!(err.status_code(), 500);
        Ok(())
    }

    #[test]
    fn test_validate_transition_error_message_contains_states(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = validate_transition(Some(SessionState::Expired), SessionState::Pending);
        let err = result.err().ok_or("expected Err, got Ok")?;
        let msg = err.message();
        assert!(
            msg.contains("Expired"),
            "error message should mention prior state: {}",
            msg
        );
        assert!(
            msg.contains("Pending"),
            "error message should mention target state: {}",
            msg
        );
        Ok(())
    }

    #[test]
    fn test_validate_transition_error_message_contains_invalid(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = validate_transition(Some(SessionState::Revoked), SessionState::Verified);
        let err = result.err().ok_or("expected Err, got Ok")?;
        let msg = err.message();
        assert!(
            msg.contains("Invalid"),
            "error message should contain 'Invalid': {}",
            msg
        );
        Ok(())
    }

    #[test]
    fn test_validate_transition_ok_returns_unit() -> Result<(), Box<dyn std::error::Error>> {
        validate_transition(None, SessionState::Pending)?;
        // Returns () on success; the above ? already confirms Ok.
        Ok(())
    }

    // ── validate_transition: exhaustive same-state passes ───────────────

    #[test]
    fn test_validate_transition_all_same_state_pairs_pass() {
        let all_states = [
            SessionState::Pending,
            SessionState::ProofOk,
            SessionState::Verified,
            SessionState::Expired,
            SessionState::Revoked,
        ];
        for state in &all_states {
            assert!(
                validate_transition(Some(*state), *state).is_ok(),
                "same-state transition {:?} -> {:?} should pass",
                state,
                state
            );
        }
    }

    // ── validate_transition: None prior with all states ─────────────────

    #[test]
    fn test_validate_transition_none_prior_skips_for_all_states() {
        let all_states = [
            SessionState::Pending,
            SessionState::ProofOk,
            SessionState::Verified,
            SessionState::Expired,
            SessionState::Revoked,
        ];
        for state in &all_states {
            assert!(
                validate_transition(None, *state).is_ok(),
                "None -> {:?} should always pass",
                state
            );
        }
    }

    // ── HostedNonceDOAuditEvent: deserialisation tests ──────────────────
    //
    // dispatch_hosted_nonce_events parses HostedNonceDOAuditEvent from
    // the JSON body returned by the DO. These tests cover the
    // serde_json::from_value path used in that function.

    #[test]
    fn test_nonce_audit_event_deserialize_valid() -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::json!({
            "event_type": "nonce_replay_detected",
            "severity": "critical",
            "event_category": "SECURITY_EVENT",
            "outcome": "blocked",
            "resource_id": "nonce-abc-123",
            "message": "Replay detected",
            "details": "{\"shard\":\"nonce-shard-7\"}"
        });
        let event: HostedNonceDOAuditEvent = serde_json::from_value(json)?;
        assert_eq!(event.event_type, "nonce_replay_detected");
        assert_eq!(event.outcome, "blocked");
        assert_eq!(event.resource_id, "nonce-abc-123");
        Ok(())
    }

    #[test]
    fn test_nonce_audit_event_deserialize_missing_field() {
        let json = serde_json::json!({
            "event_type": "nonce_replay_detected",
            "severity": "critical"
            // Missing required fields
        });
        let result = serde_json::from_value::<HostedNonceDOAuditEvent>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_audit_event_array_parsing() -> Result<(), Box<dyn std::error::Error>> {
        // Replicate the exact parsing pattern from dispatch_hosted_nonce_events
        let body = r#"{"audit_events":[{"event_type":"nonce_stored","severity":"info","event_category":"DATA_MUTATION","outcome":"success","resource_id":"nonce-x","message":"stored","details":"{}"}]}"#;
        let value: serde_json::Value = serde_json::from_str(body)?;
        let array = value
            .get("audit_events")
            .and_then(|v| v.as_array())
            .ok_or("missing audit_events array")?;
        assert_eq!(array.len(), 1);
        let events: Vec<HostedNonceDOAuditEvent> = array
            .iter()
            .filter_map(|v| serde_json::from_value::<HostedNonceDOAuditEvent>(v.clone()).ok())
            .collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "nonce_stored");
        Ok(())
    }

    #[test]
    fn test_nonce_audit_event_empty_array() -> Result<(), Box<dyn std::error::Error>> {
        let body = r#"{"audit_events":[]}"#;
        let value: serde_json::Value = serde_json::from_str(body)?;
        let array = value
            .get("audit_events")
            .and_then(|v| v.as_array())
            .ok_or("missing audit_events array")?;
        assert!(array.is_empty());
        Ok(())
    }

    #[test]
    fn test_nonce_audit_event_missing_audit_events_key() -> Result<(), Box<dyn std::error::Error>> {
        let body = r#"{"result":"ok"}"#;
        let value: serde_json::Value = serde_json::from_str(body)?;
        let array = value.get("audit_events").and_then(|v| v.as_array());
        assert!(array.is_none());
        Ok(())
    }

    #[test]
    fn test_nonce_audit_event_malformed_json_body() {
        let body = "not valid json {{{";
        let result = serde_json::from_str::<serde_json::Value>(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_audit_event_mixed_valid_and_invalid() -> Result<(), Box<dyn std::error::Error>> {
        // The filter_map pattern in dispatch_hosted_nonce_events silently drops
        // events that fail deserialisation. Verify that behaviour.
        let body = serde_json::json!({
            "audit_events": [
                {
                    "event_type": "valid_event",
                    "severity": "info",
                    "event_category": "DATA_MUTATION",
                    "outcome": "success",
                    "resource_id": "r1",
                    "message": "ok",
                    "details": "{}"
                },
                {
                    "broken": true
                },
                {
                    "event_type": "another_valid",
                    "severity": "warning",
                    "event_category": "SECURITY_EVENT",
                    "outcome": "flagged",
                    "resource_id": "r2",
                    "message": "warning",
                    "details": "{}"
                }
            ]
        });
        let array = body
            .get("audit_events")
            .and_then(|v| v.as_array())
            .ok_or("missing audit_events")?;
        let events: Vec<HostedNonceDOAuditEvent> = array
            .iter()
            .filter_map(|v| serde_json::from_value::<HostedNonceDOAuditEvent>(v.clone()).ok())
            .collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "valid_event");
        assert_eq!(events[1].event_type, "another_valid");
        Ok(())
    }

    #[test]
    fn test_nonce_audit_event_audit_events_not_array() -> Result<(), Box<dyn std::error::Error>> {
        // audit_events is present but not an array
        let body = r#"{"audit_events":"not_an_array"}"#;
        let value: serde_json::Value = serde_json::from_str(body)?;
        let array = value.get("audit_events").and_then(|v| v.as_array());
        assert!(array.is_none());
        Ok(())
    }

    // ── get_shard_name: numeric stability edge cases ────────────────────

    #[test]
    fn test_shard_name_shard_count_one_always_zero() {
        // Verify every key goes to shard-0 when only one shard exists
        for i in 0..100 {
            let key = format!("key-{}", i);
            let name = get_shard_name("pfx", &key, 1);
            assert_eq!(name, "pfx-shard-0");
        }
    }

    #[test]
    fn test_shard_name_consistent_across_calls() {
        // Determinism check with varied inputs
        let cases = vec![
            ("nonce", "abc", 25),
            ("session", "xyz-123", 10),
            ("nonce", "", 1),
            ("", "", 5),
        ];
        for (prefix, key, count) in &cases {
            let r1 = get_shard_name(prefix, key, *count);
            let r2 = get_shard_name(prefix, key, *count);
            assert_eq!(
                r1, r2,
                "non-deterministic for ({}, {}, {})",
                prefix, key, count
            );
        }
    }

    // ── validate_transition: verify all invalid transitions produce Err ──

    #[test]
    fn test_validate_transition_all_invalid_cross_state_pairs() {
        // Enumerate every (from, to) pair that should be invalid
        let invalid_pairs = vec![
            (SessionState::Pending, SessionState::Verified),
            (SessionState::ProofOk, SessionState::Pending),
            (SessionState::Verified, SessionState::Pending),
            (SessionState::Verified, SessionState::ProofOk),
            (SessionState::Verified, SessionState::Expired),
            (SessionState::Verified, SessionState::Revoked),
            (SessionState::Expired, SessionState::Pending),
            (SessionState::Expired, SessionState::ProofOk),
            (SessionState::Expired, SessionState::Verified),
            (SessionState::Expired, SessionState::Revoked),
            (SessionState::Revoked, SessionState::Pending),
            (SessionState::Revoked, SessionState::ProofOk),
            (SessionState::Revoked, SessionState::Verified),
            (SessionState::Revoked, SessionState::Expired),
        ];
        for (from, to) in &invalid_pairs {
            assert!(
                validate_transition(Some(*from), *to).is_err(),
                "{:?} -> {:?} should be invalid",
                from,
                to
            );
        }
    }

    #[test]
    fn test_validate_transition_all_valid_cross_state_pairs() {
        // Enumerate every (from, to) pair that should be valid (non-self)
        let valid_pairs = vec![
            (SessionState::Pending, SessionState::ProofOk),
            (SessionState::Pending, SessionState::Expired),
            (SessionState::Pending, SessionState::Revoked),
            (SessionState::ProofOk, SessionState::Verified),
            (SessionState::ProofOk, SessionState::Expired),
            (SessionState::ProofOk, SessionState::Revoked),
        ];
        for (from, to) in &valid_pairs {
            assert!(
                validate_transition(Some(*from), *to).is_ok(),
                "{:?} -> {:?} should be valid",
                from,
                to
            );
        }
    }

    // ── Nonce request body serialisation ────────────────────────────────
    //
    // store_nonce_do builds a JSON body with `nonce` and `ttl_seconds`.
    // Test that the serialisation matches what CheckAndSetRequest expects.

    #[test]
    fn test_nonce_request_body_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let body = serde_json::json!({
            "nonce": "test-nonce-value",
            "ttl_seconds": 300u64
        });
        let body_str = serde_json::to_string(&body)?;
        assert!(body_str.contains("test-nonce-value"));
        assert!(body_str.contains("300"));

        // Verify it round-trips through serde_json::Value
        let parsed: serde_json::Value = serde_json::from_str(&body_str)?;
        assert_eq!(
            parsed.get("nonce").and_then(|v| v.as_str()),
            Some("test-nonce-value")
        );
        assert_eq!(
            parsed.get("ttl_seconds").and_then(|v| v.as_u64()),
            Some(300)
        );
        Ok(())
    }

    // ── HostedSession serialisation round-trip via KV path ──────────────
    //
    // store_session_kv serializes to JSON then encrypts. get_session_kv
    // decrypts then deserializes. Test the JSON serialisation step.

    #[test]
    fn test_session_serialization_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let session = HostedSession::new(
            "sess-kv-test".to_string(),
            "pk_live_abc".to_string(),
            "https://example.com".to_string(),
            "challenge-hash-xyz".to_string(),
            "verifier-secret-123".to_string(),
            "vcid-456".to_string(),
            "nonce-def".to_string(),
            9999999999,
            "sandbox".to_string(),
        );
        let json = serde_json::to_string(&session)?;
        let deserialized: HostedSession = serde_json::from_str(&json)?;
        assert_eq!(deserialized.session_id, "sess-kv-test");
        assert_eq!(deserialized.public_key, "pk_live_abc");
        assert_eq!(deserialized.origin, "https://example.com");
        assert_eq!(deserialized.state, SessionState::Pending);
        assert_eq!(deserialized.code_challenge, "challenge-hash-xyz");
        assert_eq!(deserialized.code_verifier, "verifier-secret-123");
        assert_eq!(deserialized.verifier_challenge_id, "vcid-456");
        assert_eq!(deserialized.nonce, "nonce-def");
        assert_eq!(deserialized.expires_at, 9999999999);
        assert_eq!(deserialized.environment, "sandbox");
        assert_eq!(deserialized.status_check_count, 0);
        assert_eq!(deserialized.redeem_attempt_count, 0);
        assert!(deserialized.credential_data.is_none());
        assert!(deserialized.error.is_none());
        assert!(deserialized.proof_submitted_at.is_none());
        assert!(deserialized.verified_at.is_none());
        Ok(())
    }

    #[test]
    fn test_session_serialization_with_optional_fields() -> Result<(), Box<dyn std::error::Error>> {
        let mut session = HostedSession::new(
            "sess-opt".to_string(),
            "pk_test".to_string(),
            "https://test.com".to_string(),
            "ch".to_string(),
            "cv".to_string(),
            "vcid".to_string(),
            "n".to_string(),
            9999999999,
            "production".to_string(),
        );
        session.user_agent = Some("Mozilla/5.0".to_string());
        session.client_ip_hash = Some("abcdef1234".to_string());
        session.credential_data = Some("cred-data-encrypted".to_string());
        session.error = Some("timeout".to_string());
        session.proof_submitted_at = Some(1700000000);
        session.verified_at = Some(1700000001);
        session.status_check_count = 5;
        session.redeem_attempt_count = 2;
        session.verifying_key_id = Some(42);

        let json = serde_json::to_string(&session)?;
        let d: HostedSession = serde_json::from_str(&json)?;
        assert_eq!(d.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(d.client_ip_hash.as_deref(), Some("abcdef1234"));
        assert_eq!(d.credential_data.as_deref(), Some("cred-data-encrypted"));
        assert_eq!(d.error.as_deref(), Some("timeout"));
        assert_eq!(d.proof_submitted_at, Some(1700000000));
        assert_eq!(d.verified_at, Some(1700000001));
        assert_eq!(d.status_check_count, 5);
        assert_eq!(d.redeem_attempt_count, 2);
        assert_eq!(d.verifying_key_id, Some(42));
        Ok(())
    }

    #[test]
    fn test_session_deserialization_rejects_unknown_fields() {
        let json = r#"{
            "session_id":"s","public_key":"p","origin":"o","state":"pending",
            "code_challenge":"c","code_verifier":"v","verifier_challenge_id":"vi",
            "nonce":"n","expires_at":99,"created_at":1,"last_activity_at":1,
            "unknown_field":"boom"
        }"#;
        let result = serde_json::from_str::<HostedSession>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown_field"
        );
    }

    #[test]
    fn test_session_state_serde_all_variants() -> Result<(), Box<dyn std::error::Error>> {
        let pairs = vec![
            (SessionState::Pending, r#""pending""#),
            (SessionState::ProofOk, r#""proof_ok_waiting_for_redeem""#),
            (SessionState::Verified, r#""verified""#),
            (SessionState::Expired, r#""expired""#),
            (SessionState::Revoked, r#""revoked""#),
        ];
        for (state, expected_json) in &pairs {
            let serialized = serde_json::to_string(state)?;
            assert_eq!(
                &serialized, expected_json,
                "serialization mismatch for {:?}",
                state
            );
            let deserialized: SessionState = serde_json::from_str(expected_json)?;
            assert_eq!(
                &deserialized, state,
                "deserialization mismatch for {}",
                expected_json
            );
        }
        Ok(())
    }

    // ── TTL remaining calculation (from update_session_kv_checked) ───────
    //
    // update_session_kv_checked computes:
    //   remaining = session.expires_at.saturating_sub(now).max(60)
    // Test the arithmetic without the async context.

    #[test]
    fn test_ttl_remaining_calculation_future_expiry() {
        let now: u64 = 1700000000;
        let expires_at: u64 = 1700003600; // 1 hour from now
        let remaining = expires_at.saturating_sub(now).max(60);
        assert_eq!(remaining, 3600);
    }

    #[test]
    fn test_ttl_remaining_calculation_past_expiry() {
        let now: u64 = 1700003600;
        let expires_at: u64 = 1700000000; // Already expired
        let remaining = expires_at.saturating_sub(now).max(60);
        assert_eq!(remaining, 60, "floor of 60s should be applied");
    }

    #[test]
    fn test_ttl_remaining_calculation_exactly_now() {
        let now: u64 = 1700000000;
        let expires_at: u64 = 1700000000;
        let remaining = expires_at.saturating_sub(now).max(60);
        assert_eq!(remaining, 60, "zero remaining should floor to 60");
    }

    #[test]
    fn test_ttl_remaining_calculation_near_expiry() {
        let now: u64 = 1700000000;
        let expires_at: u64 = 1700000030; // 30s from now
        let remaining = expires_at.saturating_sub(now).max(60);
        assert_eq!(remaining, 60, "30s remaining should floor to 60");
    }

    #[test]
    fn test_ttl_remaining_calculation_exactly_at_floor() {
        let now: u64 = 1700000000;
        let expires_at: u64 = 1700000060; // exactly 60s from now
        let remaining = expires_at.saturating_sub(now).max(60);
        assert_eq!(remaining, 60);
    }

    #[test]
    fn test_ttl_remaining_calculation_one_above_floor() {
        let now: u64 = 1700000000;
        let expires_at: u64 = 1700000061; // 61s from now
        let remaining = expires_at.saturating_sub(now).max(60);
        assert_eq!(remaining, 61);
    }

    // ── redact_session_id usage pattern ─────────────────────────────────
    //
    // KV logging uses redact_session_id. Verify it matches expectations
    // for the session IDs used in this module.

    #[test]
    fn test_redact_session_id_for_uuid() {
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let redacted = redact_session_id(session_id);
        assert_eq!(redacted, "550e8400");
        assert!(!redacted.contains('-'));
    }

    #[test]
    fn test_redact_session_id_short_input() {
        let session_id = "ab";
        let redacted = redact_session_id(session_id);
        assert_eq!(redacted, "ab");
    }

    #[test]
    fn test_redact_session_id_empty_input() {
        let session_id = "";
        let redacted = redact_session_id(session_id);
        assert_eq!(redacted, "");
    }

    #[test]
    fn test_redact_session_id_exactly_eight_chars() {
        let session_id = "12345678";
        let redacted = redact_session_id(session_id);
        assert_eq!(redacted, "12345678");
    }

    #[test]
    fn test_redact_session_id_nine_chars() {
        let session_id = "123456789";
        let redacted = redact_session_id(session_id);
        assert_eq!(redacted, "12345678");
    }

    // ── Nonce shard count constant ──────────────────────────────────────
    //
    // store_nonce_do uses NONCE_SHARD_COUNT = 25. Verify the shard name
    // matches the expected range for 25 shards.

    #[test]
    fn test_nonce_shard_count_25_range() -> Result<(), Box<dyn std::error::Error>> {
        let shard_count = 25usize;
        for i in 0..200 {
            let nonce = format!("nonce-test-{}", i);
            let shard_name = get_shard_name("nonce", &nonce, shard_count);
            let num: usize = shard_name
                .strip_prefix("nonce-shard-")
                .ok_or("missing prefix")?
                .parse()?;
            assert!(num < shard_count, "shard {} out of range", num);
        }
        Ok(())
    }

    // ── ApiError construction from validate_transition ───────────────────

    #[test]
    fn test_validate_transition_error_serializes() -> Result<(), Box<dyn std::error::Error>> {
        let result = validate_transition(Some(SessionState::Verified), SessionState::Pending);
        let err = result.err().ok_or("expected Err, got Ok")?;
        // HostedApiError implements Serialize
        let json = serde_json::to_string(&err)?;
        assert!(json.contains("InternalError"));
        assert!(json.contains("Verified"));
        assert!(json.contains("Pending"));
        Ok(())
    }

    #[test]
    fn test_validate_transition_error_display() -> Result<(), Box<dyn std::error::Error>> {
        let result = validate_transition(Some(SessionState::Revoked), SessionState::ProofOk);
        let err = result.err().ok_or("expected Err, got Ok")?;
        let display = format!("{}", err);
        assert!(display.contains("Revoked"));
        assert!(display.contains("ProofOk"));
        Ok(())
    }
}
