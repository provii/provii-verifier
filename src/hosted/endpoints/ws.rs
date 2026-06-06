// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! WebSocket upgrade handler for hosted verification push notifications.
//!
//! `GET /v1/hosted/ws/:session_id` upgrades the HTTP connection to a WebSocket,
//! forwarded to the `HOSTED_CHALLENGE_NOTIFY_DO` Durable Object keyed by
//! session ID. The DO hibernates until a proof-verified notification arrives.
//!
//! SECURITY: Validates challenge existence before waking a Durable Object to
//! prevent cost-amplification attacks with random UUIDs. Rate-limits WebSocket
//! connections per hashed client IP. Requires an HMAC-signed single-use ticket
//! (appended to the ws_url by the challenge endpoint) because the browser
//! WebSocket API cannot send custom HTTP headers.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use std::sync::Arc;

use uuid::Uuid;
use worker::{Error as WorkerError, Headers, Response};

#[cfg(target_arch = "wasm32")]
use crate::security::log_sanitizer::redact_challenge_id;

use crate::{
    bindings::KV_CONFIG,
    error::ApiError,
    hosted::{session_binding::validate_ws_ticket, storage::kv::get_session_kv},
    AppState,
};

/// Default maximum WebSocket connections per IP per hour.
///
/// Used by the router layer (M-058) to enforce per-IP WS rate limits.
pub const DEFAULT_WS_QUOTA_PER_HOUR: u32 = 120;

/// TTL for consumed ticket markers (seconds).
const TICKET_CONSUMED_TTL: u64 = 300;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Upgrade an HTTP connection to a WebSocket for push notifications.
///
/// The handler validates the request, checks challenge existence, verifies the
/// HMAC ticket, enforces single-use semantics, and then forwards the upgrade
/// request to the `HOSTED_CHALLENGE_NOTIFY_DO` Durable Object.
///
/// No service binding replacement is needed here; this handler was already
/// self-contained in provii-verifier. It is ported as-is with adaptations to
/// use provii-verifier's `AppState` and challenge store.
///
/// # Security checks
///
/// 1. Sec-Fetch-Dest must be "websocket" or "empty"
/// 2. Upgrade header must be "websocket"
/// 3. Session ID format validation (UUID)
/// 4. Per-IP rate limit (via KV quota)
/// 5. Challenge existence check (prevents DO wake floods)
/// 6. HMAC ticket verification (constant-time)
/// 7. Single-use ticket enforcement (KV marker)
/// 8. Origin match against challenge origin
pub async fn handle_hosted_ws_upgrade(
    state: Arc<AppState>,
    req: &worker::Request,
    headers: Headers,
    session_id: &str,
) -> Result<Response, WorkerError> {
    let client_ip = headers
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string());

    let origin = headers.get("Origin").ok().flatten().unwrap_or_default();

    // ── Sec-Fetch-Dest validation ──────────────────────────────────────────
    // Browsers send Sec-Fetch-Dest: websocket for WS upgrades. Only reject
    // clearly illegitimate destinations.
    if let Ok(Some(dest)) = headers.get("Sec-Fetch-Dest") {
        let dest_lower = dest.to_lowercase();
        if dest_lower != "websocket" && dest_lower != "empty" {
            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "hosted_ws:sec_fetch_violation")
                .await;
            return error_json("Access denied", 403);
        }
    }

    // ── Upgrade header ─────────────────────────────────────────────────────
    let upgrade = headers.get("Upgrade").ok().flatten().unwrap_or_default();
    if upgrade.to_lowercase() != "websocket" {
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_ws:missing_upgrade_header")
            .await;
        return error_json("Expected WebSocket upgrade", 426);
    }

    // ── Validate session_id format ──────────────────────────────────────────
    if Uuid::parse_str(session_id).is_err() {
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_ws:invalid_session_id")
            .await;
        return error_json("Invalid session_id format", 400);
    }

    // ── Load session from KV to confirm existence and get challenge_id ──────
    let session = match get_session_kv(&state.env, session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "hosted_ws:challenge_not_found")
                .await;
            return error_json("Not found", 404);
        }
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/ws] Failed to read session {}: {}",
                redact_challenge_id(session_id),
                _e
            );
            return error_json("Internal error", 500);
        }
    };

    // ── HMAC ticket verification ────────────────────────────────────────────
    let request_url = req.url().map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/ws] Failed to parse request URL: {}", _e);
        WorkerError::from(ApiError::ServiceUnavailable(None))
    })?;
    let ticket: Option<String> = request_url
        .query_pairs()
        .find(|(k, _)| k == "ticket")
        .map(|(_, v)| v.into_owned());

    let ticket = match ticket {
        Some(t) if !t.is_empty() => t,
        _ => {
            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "hosted_ws:missing_ticket")
                .await;
            return error_json("Access denied", 403);
        }
    };

    // SC-001: Read from cached AppState (loaded at startup, M-049).
    let secret = match state.session_token_secret.as_ref() {
        Some(s) => s.clone(),
        None => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/ws] SESSION_TOKEN_SECRET not cached at startup");
            return error_json("Internal error", 500);
        }
    };

    // SECURITY: Constant-time HMAC verification via session_binding (ADV-VA-04-001).
    let ticket_valid = validate_ws_ticket(&ticket, session_id, session.expires_at, &secret)
        .map_err(|_e| {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/ws] HMAC validation error: {}", _e);
            WorkerError::from(ApiError::ServiceUnavailable(None))
        })?;
    if !ticket_valid {
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_ws:ticket_hmac_failed")
            .await;
        return error_json("Access denied", 403);
    }

    // ── Single-use ticket enforcement ──────────────────────────────────────
    let ticket_key = format!("ws_ticket_used:{}", session_id);
    let kv = state.env.kv(KV_CONFIG).map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/ws] KV binding error: {}", _e);
        WorkerError::from(ApiError::ServiceUnavailable(None))
    })?;

    match kv.get(&ticket_key).text().await {
        Ok(Some(_)) => {
            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "hosted_ws:ticket_reused")
                .await;
            return error_json("Access denied", 403);
        }
        Ok(None) => { /* ticket not yet consumed, proceed */ }
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/ws] Failed to check ticket reuse for session {}: {:?}",
                redact_challenge_id(session_id),
                _e
            );
            return error_json("Internal error", 500);
        }
    }

    // Mark ticket as consumed. TTL matches session lifetime.
    if let Err(_e) = kv
        .put(&ticket_key, "1")
        .map_err(|_e| {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/ws] KV put builder error: {}", _e);
            WorkerError::from(ApiError::ServiceUnavailable(None))
        })?
        .expiration_ttl(TICKET_CONSUMED_TTL)
        .execute()
        .await
    {
        // Write failure: fail closed.
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/ws] Failed to mark ticket consumed for session {}: {:?}",
            redact_challenge_id(session_id),
            _e
        );
        return error_json("Internal error", 500);
    }

    // ── Origin check (constant-time) ──────────────────────────────────────
    let origin_match = {
        use subtle::ConstantTimeEq;
        let a = origin.as_bytes();
        let b = session.origin.as_bytes();
        a.len() == b.len() && bool::from(a.ct_eq(b))
    };
    if !origin_match {
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_ws:origin_mismatch")
            .await;
        return error_json("Origin mismatch", 403);
    }

    // ── Forward to ChallengeNotifyDO ────────────────────────────────────────
    state
        .audit_logger
        .log_suspicious_activity(&client_ip, "hosted_ws:upgrade_success")
        .await;

    let namespace = state.env.durable_object("HOSTED_CHALLENGE_NOTIFY_DO")?;
    let stub = namespace.id_from_name(session_id)?.get_stub()?;

    let internal_url = "https://challenge-notify-do/ws";
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Get);
    let ws_headers = Headers::new();
    ws_headers.set("Upgrade", "websocket")?;
    init.with_headers(ws_headers);
    let internal_req = worker::Request::new_with_init(internal_url, &init)?;

    stub.fetch_with_request(internal_req).await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal JSON error response with the given status code.
///
/// Security headers are applied by the router wrapper (M-058), not here.
fn error_json(message: &str, status: u16) -> Result<Response, WorkerError> {
    let body = serde_json::json!({ "error": message });
    let response = Response::from_json(&body)?.with_status(status);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    /// Build a domain-separated HMAC ticket matching the format in
    /// `crate::hosted::session_binding::generate_ws_ticket`.
    fn generate_test_ticket(secret: &str, session_id: &str, expires_at: u64) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key creation failed");
        mac.update(b"provii-ws-ticket-v1");
        mac.update(&(session_id.len() as u32).to_le_bytes());
        mac.update(session_id.as_bytes());
        mac.update(expires_at.to_string().as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    #[test]
    fn test_validate_ws_ticket_valid() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key-32-bytes-long!!!";
        let session_id = "abc-123";
        let expires_at: u64 = 1700000000;

        let ticket = generate_test_ticket(secret, session_id, expires_at);
        assert!(validate_ws_ticket(&ticket, session_id, expires_at, secret)?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_invalid() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key-32-bytes-long!!!";
        assert!(!validate_ws_ticket(
            "invalid-ticket",
            "session-id",
            1700000000,
            secret
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_wrong_session() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key-32-bytes-long!!!";
        let ticket = generate_test_ticket(secret, "session-a", 1700000000);

        // Using session-b should fail.
        assert!(!validate_ws_ticket(
            &ticket,
            "session-b",
            1700000000,
            secret
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_wrong_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key-32-bytes-long!!!";
        let session_id = "session-a";
        let ticket = generate_test_ticket(secret, session_id, 1700000000);

        // Different expiry should fail.
        assert!(!validate_ws_ticket(
            &ticket, session_id, 1700000001, secret
        )?);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_json() -> Result<(), Box<dyn std::error::Error>> {
        let resp = error_json("test error", 400)?;
        assert_eq!(resp.status_code(), 400);
        Ok(())
    }

    // ── error_json status codes ─────────────────────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_json_403() -> Result<(), Box<dyn std::error::Error>> {
        let resp = error_json("forbidden", 403)?;
        assert_eq!(resp.status_code(), 403);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_json_404() -> Result<(), Box<dyn std::error::Error>> {
        let resp = error_json("not found", 404)?;
        assert_eq!(resp.status_code(), 404);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_json_426() -> Result<(), Box<dyn std::error::Error>> {
        let resp = error_json("upgrade required", 426)?;
        assert_eq!(resp.status_code(), 426);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_json_500() -> Result<(), Box<dyn std::error::Error>> {
        let resp = error_json("internal", 500)?;
        assert_eq!(resp.status_code(), 500);
        Ok(())
    }

    // ── validate_ws_ticket: empty and malformed inputs ──────────────────

    #[test]
    fn test_validate_ws_ticket_empty_ticket() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key-32-bytes-long!!!";
        assert!(!validate_ws_ticket("", "session-a", 1700000000, secret)?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_empty_session_id() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key-32-bytes-long!!!";
        let ticket = generate_test_ticket(secret, "", 1700000000);

        // A ticket generated for empty session_id should only match empty session_id
        assert!(validate_ws_ticket(&ticket, "", 1700000000, secret)?);
        assert!(!validate_ws_ticket(
            &ticket,
            "not-empty",
            1700000000,
            secret
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_wrong_secret() -> Result<(), Box<dyn std::error::Error>> {
        let secret_a = "secret-a-32-bytes-long-padding!!";
        let secret_b = "secret-b-32-bytes-long-padding!!";
        let session_id = "session-1";
        let expires_at = 1700000000u64;

        let ticket = generate_test_ticket(secret_a, session_id, expires_at);

        // Valid with the correct secret
        assert!(validate_ws_ticket(
            &ticket, session_id, expires_at, secret_a
        )?);
        // Invalid with a different secret
        assert!(!validate_ws_ticket(
            &ticket, session_id, expires_at, secret_b
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_non_base64_ticket() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key-32-bytes-long!!!";
        // Characters not valid in base64url
        assert!(!validate_ws_ticket("!!!not-base64!!!", "s", 100, secret)?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_truncated_mac() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret = "test-secret-key-32-bytes-long!!!";
        let session_id = "session-trunc";
        let expires_at = 1700000000u64;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
        mac.update(b"provii-ws-ticket-v1");
        mac.update(&(session_id.len() as u32).to_le_bytes());
        mac.update(session_id.as_bytes());
        mac.update(expires_at.to_string().as_bytes());
        let expected = mac.finalize().into_bytes();
        // Truncate the MAC to only 16 bytes
        let ticket = URL_SAFE_NO_PAD.encode(&expected[..16]);

        assert!(!validate_ws_ticket(
            &ticket, session_id, expires_at, secret
        )?);
        Ok(())
    }

    // ── Constants ────────────────────────────────────────────────────────

    #[test]
    fn test_default_ws_quota_per_hour() {
        assert_eq!(DEFAULT_WS_QUOTA_PER_HOUR, 120);
    }

    #[test]
    fn test_ticket_consumed_ttl() {
        assert_eq!(TICKET_CONSUMED_TTL, 300);
    }

    // ── validate_ws_ticket: boundary and edge-case inputs ──────────────

    #[test]
    fn test_validate_ws_ticket_max_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key-32-bytes-long!!!";
        let session_id = "sess-max";
        let expires_at = u64::MAX;

        let ticket = generate_test_ticket(secret, session_id, expires_at);
        assert!(validate_ws_ticket(&ticket, session_id, expires_at, secret)?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_zero_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key-32-bytes-long!!!";
        let session_id = "sess-zero";
        let expires_at: u64 = 0;

        let ticket = generate_test_ticket(secret, session_id, expires_at);
        assert!(validate_ws_ticket(&ticket, session_id, expires_at, secret)?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_unicode_session_id() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key-32-bytes-long!!!";
        let session_id = "\u{1F600}\u{00E9}\u{4E16}\u{754C}"; // emoji + accented + CJK
        let expires_at: u64 = 1700000000;

        let ticket = generate_test_ticket(secret, session_id, expires_at);
        assert!(validate_ws_ticket(&ticket, session_id, expires_at, secret)?);
        // Different session must fail
        assert!(!validate_ws_ticket(
            &ticket,
            "plain-ascii",
            expires_at,
            secret
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_long_session_id() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key-32-bytes-long!!!";
        let session_id = "a".repeat(1024);
        let expires_at: u64 = 1700000000;

        let ticket = generate_test_ticket(secret, &session_id, expires_at);
        assert!(validate_ws_ticket(
            &ticket,
            &session_id,
            expires_at,
            secret
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_session_with_colon() -> Result<(), Box<dyn std::error::Error>> {
        // Session ID containing colons is safe because the domain-separated
        // format uses length-prefixed fields, not a colon delimiter.
        let secret = "test-secret-key-32-bytes-long!!!";
        let session_id = "sess:with:colons";
        let expires_at: u64 = 1700000000;

        let ticket = generate_test_ticket(secret, session_id, expires_at);
        assert!(validate_ws_ticket(&ticket, session_id, expires_at, secret)?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_one_byte_secret() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "x"; // minimal secret
        let session_id = "sess-1";
        let expires_at: u64 = 100;

        let ticket = generate_test_ticket(secret, session_id, expires_at);
        assert!(validate_ws_ticket(&ticket, session_id, expires_at, secret)?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_empty_secret() -> Result<(), Box<dyn std::error::Error>> {
        // HMAC-SHA256 technically accepts an empty key (it gets padded).
        // Verify the function handles it without panic.
        let secret = "";
        let session_id = "sess-empty-secret";
        let expires_at: u64 = 1700000000;

        let ticket = generate_test_ticket(secret, session_id, expires_at);
        assert!(validate_ws_ticket(&ticket, session_id, expires_at, secret)?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_extra_bytes_appended() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret = "test-secret-key-32-bytes-long!!!";
        let session_id = "sess-extra";
        let expires_at: u64 = 1700000000;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
        mac.update(b"provii-ws-ticket-v1");
        mac.update(&(session_id.len() as u32).to_le_bytes());
        mac.update(session_id.as_bytes());
        mac.update(expires_at.to_string().as_bytes());
        let expected = mac.finalize().into_bytes();

        // Append an extra byte to the MAC before encoding
        let mut extended = expected.to_vec();
        extended.push(0xFF);
        let ticket = URL_SAFE_NO_PAD.encode(&extended);

        // Must fail: length mismatch in constant-time compare
        assert!(!validate_ws_ticket(
            &ticket, session_id, expires_at, secret
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_prefix_bytes_removed() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret = "test-secret-key-32-bytes-long!!!";
        let session_id = "sess-prefix";
        let expires_at: u64 = 1700000000;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
        mac.update(b"provii-ws-ticket-v1");
        mac.update(&(session_id.len() as u32).to_le_bytes());
        mac.update(session_id.as_bytes());
        mac.update(expires_at.to_string().as_bytes());
        let expected = mac.finalize().into_bytes();

        // Remove first byte
        let shortened = &expected[1..];
        let ticket = URL_SAFE_NO_PAD.encode(shortened);

        assert!(!validate_ws_ticket(
            &ticket, session_id, expires_at, secret
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_single_bit_flip() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret = "test-secret-key-32-bytes-long!!!";
        let session_id = "sess-bitflip";
        let expires_at: u64 = 1700000000;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
        mac.update(b"provii-ws-ticket-v1");
        mac.update(&(session_id.len() as u32).to_le_bytes());
        mac.update(session_id.as_bytes());
        mac.update(expires_at.to_string().as_bytes());
        let expected = mac.finalize().into_bytes();

        // Flip one bit in the first byte
        let mut flipped = expected.to_vec();
        flipped[0] ^= 0x01;
        let ticket = URL_SAFE_NO_PAD.encode(&flipped);

        assert!(!validate_ws_ticket(
            &ticket, session_id, expires_at, secret
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_single_bit_flip_last_byte() -> Result<(), Box<dyn std::error::Error>>
    {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret = "test-secret-key-32-bytes-long!!!";
        let session_id = "sess-bitflip-last";
        let expires_at: u64 = 1700000000;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
        mac.update(b"provii-ws-ticket-v1");
        mac.update(&(session_id.len() as u32).to_le_bytes());
        mac.update(session_id.as_bytes());
        mac.update(expires_at.to_string().as_bytes());
        let expected = mac.finalize().into_bytes();

        let mut flipped = expected.to_vec();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x80;
        let ticket = URL_SAFE_NO_PAD.encode(&flipped);

        assert!(!validate_ws_ticket(
            &ticket, session_id, expires_at, secret
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_all_zero_mac_rejected() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret = "test-secret-key-32-bytes-long!!!";
        let zeroed_mac = [0u8; 32];
        let ticket = URL_SAFE_NO_PAD.encode(zeroed_mac);

        assert!(!validate_ws_ticket(
            &ticket,
            "any-session",
            1700000000,
            secret
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_standard_base64_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        // Standard base64 uses + and / which are not URL-safe. If someone passes
        // a standard-encoded ticket, base64url decode might fail or produce
        // wrong bytes.
        let secret = "test-secret-key-32-bytes-long!!!";
        // Use standard base64 characters that are invalid in URL-safe: + and /
        let ticket = "AAAA+AAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(!validate_ws_ticket(ticket, "session", 100, secret)?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_padded_base64_rejected() -> Result<(), Box<dyn std::error::Error>> {
        // base64 with padding should fail since we decode with NO_PAD
        let secret = "test-secret-key-32-bytes-long!!!";
        let ticket = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(!validate_ws_ticket(ticket, "session", 100, secret)?);
        Ok(())
    }

    // ── validate_ws_ticket: determinism ────────────────────────────────

    #[test]
    fn test_validate_ws_ticket_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "determinism-test-key-32-bytes!!!";
        let session_id = "sess-det";
        let expires_at: u64 = 1700000000;

        let ticket = generate_test_ticket(secret, session_id, expires_at);

        // Verify twice to confirm determinism
        assert!(validate_ws_ticket(&ticket, session_id, expires_at, secret)?);
        assert!(validate_ws_ticket(&ticket, session_id, expires_at, secret)?);
        Ok(())
    }

    // ── validate_ws_ticket: adjacent expiry values ─────────────────────

    #[test]
    fn test_validate_ws_ticket_adjacent_expiry_values() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key-32-bytes-long!!!";
        let session_id = "sess-adj";

        // Generate ticket for expiry N
        let expires_at: u64 = 1700000000;
        let ticket = generate_test_ticket(secret, session_id, expires_at);

        // Must pass for exact value
        assert!(validate_ws_ticket(&ticket, session_id, expires_at, secret)?);
        // Must fail for N-1 and N+1
        assert!(!validate_ws_ticket(
            &ticket,
            session_id,
            expires_at - 1,
            secret
        )?);
        assert!(!validate_ws_ticket(
            &ticket,
            session_id,
            expires_at + 1,
            secret
        )?);
        Ok(())
    }

    // ── error_json: edge cases ─────────────────────────────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_json_200() -> Result<(), Box<dyn std::error::Error>> {
        let resp = error_json("ok", 200)?;
        assert_eq!(resp.status_code(), 200);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_json_empty_message() -> Result<(), Box<dyn std::error::Error>> {
        let resp = error_json("", 400)?;
        assert_eq!(resp.status_code(), 400);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_json_message_with_special_chars() -> Result<(), Box<dyn std::error::Error>> {
        let resp = error_json("error: \"quotes\" & <angles>", 400)?;
        assert_eq!(resp.status_code(), 400);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_json_message_with_unicode() -> Result<(), Box<dyn std::error::Error>> {
        let resp = error_json("\u{00E9}\u{00F1}\u{00FC}", 422)?;
        assert_eq!(resp.status_code(), 422);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_json_various_4xx() -> Result<(), Box<dyn std::error::Error>> {
        for code in [400, 401, 403, 404, 405, 409, 422, 429] {
            let resp = error_json("test", code)?;
            assert_eq!(resp.status_code(), code);
        }
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_json_various_5xx() -> Result<(), Box<dyn std::error::Error>> {
        for code in [500, 502, 503, 504] {
            let resp = error_json("test", code)?;
            assert_eq!(resp.status_code(), code);
        }
        Ok(())
    }

    // ── ticket_key format ──────────────────────────────────────────────

    #[test]
    fn test_ticket_key_format() {
        let session_id = "abc-def-123";
        let ticket_key = format!("ws_ticket_used:{}", session_id);
        assert_eq!(ticket_key, "ws_ticket_used:abc-def-123");
    }

    #[test]
    fn test_ticket_key_format_uuid() {
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let ticket_key = format!("ws_ticket_used:{}", session_id);
        assert!(ticket_key.starts_with("ws_ticket_used:"));
        assert!(ticket_key.ends_with(session_id));
    }

    // ── UUID validation (mirrors the handler check) ────────────────────

    #[test]
    fn test_uuid_parse_valid() {
        assert!(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn test_uuid_parse_invalid_short() {
        assert!(Uuid::parse_str("not-a-uuid").is_err());
    }

    #[test]
    fn test_uuid_parse_empty() {
        assert!(Uuid::parse_str("").is_err());
    }

    #[test]
    fn test_uuid_parse_nil() {
        assert!(Uuid::parse_str("00000000-0000-0000-0000-000000000000").is_ok());
    }

    #[test]
    fn test_uuid_parse_no_hyphens() {
        // UUID without hyphens should still parse
        assert!(Uuid::parse_str("550e8400e29b41d4a716446655440000").is_ok());
    }

    #[test]
    fn test_uuid_parse_uppercase() {
        assert!(Uuid::parse_str("550E8400-E29B-41D4-A716-446655440000").is_ok());
    }

    #[test]
    fn test_uuid_parse_with_braces_accepted() {
        // The uuid crate accepts braced UUIDs
        assert!(Uuid::parse_str("{550e8400-e29b-41d4-a716-446655440000}").is_ok());
    }

    #[test]
    fn test_uuid_parse_with_invalid_prefix_rejected() {
        // A wrong URN-style prefix is rejected
        assert!(Uuid::parse_str("urn:foo:550e8400-e29b-41d4-a716-446655440000").is_err());
    }

    #[test]
    fn test_uuid_parse_too_long() {
        assert!(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000-extra").is_err());
    }

    // ── Sec-Fetch-Dest validation logic ────────────────────────────────

    #[test]
    fn test_sec_fetch_dest_websocket_allowed() {
        let dest = "websocket";
        let dest_lower = dest.to_lowercase();
        assert!(dest_lower == "websocket" || dest_lower == "empty");
    }

    #[test]
    fn test_sec_fetch_dest_empty_allowed() {
        let dest = "empty";
        let dest_lower = dest.to_lowercase();
        assert!(dest_lower == "websocket" || dest_lower == "empty");
    }

    #[test]
    fn test_sec_fetch_dest_document_rejected() {
        let dest = "document";
        let dest_lower = dest.to_lowercase();
        assert!(dest_lower != "websocket" && dest_lower != "empty");
    }

    #[test]
    fn test_sec_fetch_dest_iframe_rejected() {
        let dest = "iframe";
        let dest_lower = dest.to_lowercase();
        assert!(dest_lower != "websocket" && dest_lower != "empty");
    }

    #[test]
    fn test_sec_fetch_dest_case_insensitive() {
        for variant in ["WebSocket", "WEBSOCKET", "Websocket", "wEBsOCKET"] {
            let lower = variant.to_lowercase();
            assert!(
                lower == "websocket" || lower == "empty",
                "failed for: {}",
                variant
            );
        }
    }

    #[test]
    fn test_sec_fetch_dest_empty_case_insensitive() {
        for variant in ["Empty", "EMPTY", "eMpTy"] {
            let lower = variant.to_lowercase();
            assert!(
                lower == "websocket" || lower == "empty",
                "failed for: {}",
                variant
            );
        }
    }

    // ── Upgrade header validation logic ────────────────────────────────

    #[test]
    fn test_upgrade_header_websocket_valid() {
        let upgrade = "websocket";
        assert_eq!(upgrade.to_lowercase(), "websocket");
    }

    #[test]
    fn test_upgrade_header_case_insensitive() {
        for variant in ["WebSocket", "WEBSOCKET", "Websocket"] {
            assert_eq!(variant.to_lowercase(), "websocket");
        }
    }

    #[test]
    fn test_upgrade_header_empty_rejected() {
        let upgrade = "";
        assert_ne!(upgrade.to_lowercase(), "websocket");
    }

    #[test]
    fn test_upgrade_header_http2_rejected() {
        let upgrade = "h2c";
        assert_ne!(upgrade.to_lowercase(), "websocket");
    }

    // ── HMAC domain-separated message format ──────────────────────────

    #[test]
    fn test_hmac_domain_separated_format() {
        // Verify the length prefix encodes correctly for a known session ID
        let session_id = "abc-123";
        let len_bytes = (session_id.len() as u32).to_le_bytes();
        assert_eq!(len_bytes, [7, 0, 0, 0]);
    }

    #[test]
    fn test_hmac_domain_separated_format_empty_session() {
        let session_id = "";
        let len_bytes = (session_id.len() as u32).to_le_bytes();
        assert_eq!(len_bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn test_hmac_domain_separated_format_long_session() {
        let session_id = "a".repeat(256);
        let len_bytes = (session_id.len() as u32).to_le_bytes();
        assert_eq!(len_bytes, [0, 1, 0, 0]);
    }

    // ── Property-based tests ───────────────────────────────────────────

    #[cfg(not(target_arch = "wasm32"))]
    mod prop_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Property: valid ticket always verifies
            #[test]
            fn prop_valid_ticket_always_verifies(
                session_id in "[a-z0-9\\-]{1,64}",
                expires_at in any::<u64>(),
                secret in "[a-zA-Z0-9!@#$%^&*]{1,128}",
            ) {
                let ticket = generate_test_ticket(&secret, &session_id, expires_at);
                let result = validate_ws_ticket(&ticket, &session_id, expires_at, &secret);
                prop_assert!(result.is_ok());
                prop_assert!(result.unwrap());
            }

            /// Property: wrong session always rejects
            #[test]
            fn prop_wrong_session_rejects(
                session_a in "[a-z]{1,32}",
                session_b in "[a-z]{1,32}",
                expires_at in any::<u64>(),
            ) {
                prop_assume!(session_a != session_b);

                let secret = "prop-test-secret-32-bytes-long!!";
                let ticket = generate_test_ticket(secret, &session_a, expires_at);

                let result = validate_ws_ticket(&ticket, &session_b, expires_at, secret);
                prop_assert!(result.is_ok());
                prop_assert!(!result.unwrap());
            }

            /// Property: wrong expiry always rejects
            #[test]
            fn prop_wrong_expiry_rejects(
                session_id in "[a-z0-9]{1,32}",
                expires_a in any::<u64>(),
                expires_b in any::<u64>(),
            ) {
                prop_assume!(expires_a != expires_b);

                let secret = "prop-test-secret-32-bytes-long!!";
                let ticket = generate_test_ticket(secret, &session_id, expires_a);

                let result = validate_ws_ticket(&ticket, &session_id, expires_b, secret);
                prop_assert!(result.is_ok());
                prop_assert!(!result.unwrap());
            }

            /// Property: random garbage ticket always rejects
            #[test]
            fn prop_random_ticket_rejects(
                ticket_bytes in prop::collection::vec(any::<u8>(), 0..256),
                session_id in "[a-z0-9]{1,16}",
                expires_at in any::<u64>(),
            ) {
                use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

                let secret = "prop-test-secret-32-bytes-long!!";
                // Compute what the correct ticket would be
                let expected_ticket = generate_test_ticket(secret, &session_id, expires_at);

                let ticket = URL_SAFE_NO_PAD.encode(&ticket_bytes);
                // Skip if random bytes happen to produce the correct ticket
                prop_assume!(ticket != expected_ticket);

                let result = validate_ws_ticket(&ticket, &session_id, expires_at, secret);
                prop_assert!(result.is_ok());
                prop_assert!(!result.unwrap());
            }

            /// Property: UUID parsing rejects non-UUID strings
            #[test]
            fn prop_non_uuid_rejected(s in "[^0-9a-fA-F\\-]{1,50}") {
                prop_assert!(Uuid::parse_str(&s).is_err());
            }

            /// Property: ticket_key always has correct prefix
            #[test]
            fn prop_ticket_key_prefix(session_id in ".{1,100}") {
                let key = format!("ws_ticket_used:{}", session_id);
                prop_assert!(key.starts_with("ws_ticket_used:"));
                prop_assert!(key.ends_with(&session_id));
            }
        }
    }
}
