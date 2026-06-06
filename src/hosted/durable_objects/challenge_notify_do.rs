// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Challenge Notification Durable Object
//!
//! Uses Cloudflare's Hibernatable WebSocket API to push verification status
//! changes to connected browsers. Replaces polling with a single WebSocket
//! connection that hibernates at zero cost until a notification arrives.
//!
//! Flow:
//!   1. Browser opens WebSocket via GET /ws
//!   2. DO accepts connection and hibernates (zero cost while waiting)
//!   3. provii-verifier sends POST /notify after proof verification
//!   4. DO wakes, pushes status message to all connected sockets, closes them
//!   5. Alarm fires at session TTL to clean up zombie connections

use worker::*;

/// Known challenge states that the notify endpoint accepts.
///
/// Any value not in this list is rejected with a 400 response. States that
/// indicate successful proof verification are listed separately so that
/// `proof_verified` can be derived rather than hardcoded.
const SUCCESS_STATES: &[&str] = &["proof_ok_waiting_for_redeem", "verified"];
const FAILURE_STATES: &[&str] = &["pending", "failed", "expired"];

/// Session TTL alarm interval (5 minutes in milliseconds). Must match
/// the SESSION_TTL_SEC default (300s) read in hosted/endpoints/challenge.rs.
const SESSION_TTL_MS: i64 = 300_000;

/// Durable Object for WebSocket push notifications on challenge completion.
///
/// Keyed by session_id so each verification session gets its own DO instance.
/// Uses Hibernatable WebSocket API for zero-cost idle time.
#[durable_object]
pub struct ChallengeNotifyDO {
    state: State,
    #[allow(dead_code)] // Required by #[durable_object] trait
    env: Env,
}

impl DurableObject for ChallengeNotifyDO {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path();
        let method = req.method();

        match (method, path) {
            (Method::Get, "/ws") => self.handle_ws_upgrade(req).await,
            (Method::Post, "/notify") => self.handle_notify(req).await,
            _ => {
                // EIL-019: Add security headers to DO error responses
                let body = serde_json::json!({ "error": "Not Found" });
                let mut resp = Response::from_json(&body)?.with_status(404);
                resp.headers_mut()
                    .set("X-Content-Type-Options", "nosniff")?;
                resp.headers_mut().set(
                    "Cache-Control",
                    "no-store, no-cache, must-revalidate, max-age=0",
                )?;
                Ok(resp)
            }
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        // Respond to ping with pong (keepalive)
        if let WebSocketIncomingMessage::String(text) = message {
            if text == "ping" {
                ws.send_with_str("pong")?;
            }
        }
        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        // No action needed. DO auto-hibernates when no sockets remain.
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, error: Error) -> Result<()> {
        console_log!("[ChallengeNotifyDO] WebSocket error: {:?}", error);
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        // Session TTL expired. Close any remaining zombie connections.
        let sockets = self.state.get_websockets();
        for ws in sockets {
            let _ = ws.close(Some(1000), Some("Session expired"));
        }
        Response::ok("alarm_handled")
    }
}

impl ChallengeNotifyDO {
    /// Handle WebSocket upgrade request from browser.
    ///
    /// SECURITY: Creates a WebSocket pair, accepts the server side for
    /// hibernation, and schedules a 5-minute alarm to force-close zombie
    /// connections that outlive the session TTL. The alarm is only set if
    /// none is already pending, so later connections cannot defer cleanup
    /// for earlier ones.
    async fn handle_ws_upgrade(&self, _req: Request) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        let server = pair.server;
        let client = pair.client;

        // Accept the server socket for hibernation.
        // The DO will sleep until a message arrives or alarm fires.
        self.state.accept_web_socket(&server);

        // ADV-VA-03-004: Only schedule the alarm if none is currently pending.
        // Matches the NonceDO ensure_alarm_scheduled() pattern so that new
        // WebSocket connections cannot repeatedly defer the zombie cleanup
        // window for earlier connections.
        self.ensure_alarm_scheduled().await?;

        Response::from_websocket(client)
    }

    /// Schedule a cleanup alarm if none is already pending. This is a no-op
    /// when an alarm is already set, preventing later connections from
    /// deferring the TTL window.
    async fn ensure_alarm_scheduled(&self) -> Result<()> {
        let existing = self.state.storage().get_alarm().await?;
        if existing.is_none() {
            self.state.storage().set_alarm(SESSION_TTL_MS).await?;
        }
        Ok(())
    }

    /// Handle notification from internal route.
    ///
    /// SECURITY: Pushes the status change to all connected WebSockets, then
    /// closes them. The body is parsed strictly so that malformed JSON cannot
    /// produce a fake "proof_verified: true" message to WebSocket clients.
    ///
    /// Returns the number of sockets that were notified.
    async fn handle_notify(&self, mut req: Request) -> Result<Response> {
        let body: serde_json::Value = req.json().await.map_err(|e| {
            console_log!("[ChallengeNotifyDO] Invalid notify body: {:?}", e);
            Error::RustError(format!("Invalid notify body: {}", e))
        })?;

        // ADV-VA-03-010: Require the "state" field. Never default to a success
        // state, as a malformed or empty POST body would otherwise broadcast
        // proof_ok_waiting_for_redeem to all connected browsers.
        let state = match body.get("state").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                console_log!("[ChallengeNotifyDO] Missing required 'state' field in notify body");
                return Response::error("Missing required 'state' field", 400);
            }
        };

        // Validate against known state values.
        let is_known = SUCCESS_STATES.contains(&state) || FAILURE_STATES.contains(&state);
        if !is_known {
            console_log!(
                "[ChallengeNotifyDO] Unknown state value in notify body: {}",
                state
            );
            return Response::error("Unknown state value", 400);
        }

        // VA-HET-002 / ADV-VA-03-005: Derive proof_verified from the actual
        // state rather than hardcoding true for every notification.
        let proof_verified = SUCCESS_STATES.contains(&state);

        // Build the WebSocket message in the format provii-agegate expects:
        // { "type": "status_change", "status": "<state>", "proof_verified": <bool> }
        let ws_message = serde_json::json!({
            "type": "status_change",
            "status": state,
            "proof_verified": proof_verified
        });
        let message = serde_json::to_string(&ws_message).map_err(|e| {
            console_log!(
                "[ChallengeNotifyDO] Failed to serialise notify body: {:?}",
                e
            );
            Error::RustError(format!("Failed to serialise notify body: {}", e))
        })?;

        let sockets = self.state.get_websockets();
        let count = sockets.len();

        if count == 0 {
            return Response::from_json(&serde_json::json!({
                "notified": 0,
                "status": "no_connections"
            }));
        }

        for ws in sockets {
            // Send the notification, then close cleanly.
            // Errors are ignored per-socket (browser may have already disconnected).
            let _ = ws.send_with_str(&message);
            let _ = ws.close(Some(1000), Some("Notification delivered"));
        }

        Response::from_json(&serde_json::json!({
            "notified": count,
            "status": "delivered"
        }))
    }

    #[cfg(test)]
    fn is_known_state(state: &str) -> bool {
        SUCCESS_STATES.contains(&state) || FAILURE_STATES.contains(&state)
    }

    #[cfg(test)]
    fn is_success_state(state: &str) -> bool {
        SUCCESS_STATES.contains(&state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_verified_true_for_success_states() {
        assert!(ChallengeNotifyDO::is_success_state(
            "proof_ok_waiting_for_redeem"
        ));
        assert!(ChallengeNotifyDO::is_success_state("verified"));
    }

    #[test]
    fn proof_verified_false_for_failure_states() {
        assert!(!ChallengeNotifyDO::is_success_state("pending"));
        assert!(!ChallengeNotifyDO::is_success_state("failed"));
        assert!(!ChallengeNotifyDO::is_success_state("expired"));
        assert!(!ChallengeNotifyDO::is_success_state("rejected"));
    }

    #[test]
    fn unknown_state_is_neither_known_nor_success() {
        assert!(!ChallengeNotifyDO::is_known_state("bogus"));
        assert!(!ChallengeNotifyDO::is_success_state("bogus"));
        assert!(!ChallengeNotifyDO::is_known_state(""));
        assert!(!ChallengeNotifyDO::is_success_state("VERIFIED"));
    }

    #[test]
    fn all_known_states_are_recognised() {
        for s in SUCCESS_STATES.iter().chain(FAILURE_STATES.iter()) {
            assert!(
                ChallengeNotifyDO::is_known_state(s),
                "state '{}' should be known",
                s
            );
        }
    }

    #[test]
    fn session_ttl_is_five_minutes() {
        assert_eq!(SESSION_TTL_MS, 300_000);
    }
}
