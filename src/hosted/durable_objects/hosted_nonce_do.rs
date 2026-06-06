// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Hosted Nonce Durable Object implementation
//!
//! Provides replay protection for hosted verification sessions by tracking
//! used nonces. Uses 25 shards for distributed load and atomic check-and-set
//! operations.
//!
//! Ported from provii-verifier's NonceDO. Renamed to HostedNonceDO to avoid
//! collision with provii-verifier's existing NonceDO.

use provii_audit::{EventCategory, Severity};
use serde::{Deserialize, Serialize};
use worker::*;

/// Audit event data collected inside HostedNonceDO.
///
/// DOs have no access to the audit queue binding, so they embed audit event
/// data in the HTTP response body. The worker-level caller dispatches via
/// `dispatch_nonce_do_audit_events`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedNonceDOAuditEvent {
    pub event_type: String,
    pub severity: Severity,
    pub event_category: EventCategory,
    pub outcome: String,
    pub resource_id: String,
    pub message: String,
    pub details: String,
}

/// ADV-VA-030: Typed request body for check-and-set operations.
/// `deny_unknown_fields` rejects unexpected fields (matching verifier NonceDO pattern).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckAndSetRequest {
    nonce: String,
    ttl_seconds: u64,
}

/// ADV-VA-030: Maximum request body size for hosted nonce DO operations (4 KB).
/// Nonce requests contain a nonce string and TTL; anything larger is abuse.
/// Matches the verifier NonceDO's `MAX_NONCE_BODY_SIZE`.
const MAX_NONCE_BODY_SIZE: usize = 4_096;

/// Nonce record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceRecord {
    pub nonce: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub used_by: Option<String>, // Optional identifier of who used the nonce
}

/// HostedNonceDO implementation for replay protection in hosted sessions
#[durable_object]
pub struct HostedNonceDO {
    state: State,
    #[allow(dead_code)] // Required by #[durable_object] trait
    env: Env,
}

impl DurableObject for HostedNonceDO {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path();
        let method = req.method();

        // Route: GET /health - Lightweight keep-alive probe used by cron
        // pre-warm to force the DO runtime to spin up before real traffic.
        if method == Method::Get && path == "/health" {
            return Response::from_json(&serde_json::json!({"ok": true}));
        }

        // Route: POST /check-and-set - Atomically check and set nonce
        if method == Method::Post && path == "/check-and-set" {
            return self.handle_check_and_set(req).await;
        }

        // EIL-019: Add security headers to DO error responses
        {
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

impl HostedNonceDO {
    /// HTTP handler: POST /check-and-set
    ///
    /// ADV-VA-030: Uses typed `CheckAndSetRequest` with `deny_unknown_fields`
    /// and a 4 KB body size limit, matching the verifier NonceDO pattern.
    async fn handle_check_and_set(&self, mut req: Request) -> Result<Response> {
        // ADV-VA-030: Enforce body size limit before parsing.
        let body_bytes = req.bytes().await?;
        if body_bytes.len() > MAX_NONCE_BODY_SIZE {
            console_log!(
                "[HostedNonceDO] Body too large: {} > {}",
                body_bytes.len(),
                MAX_NONCE_BODY_SIZE
            );
            return Response::error("Request entity too large", 413);
        }

        // ADV-VA-030: Parse into typed struct with deny_unknown_fields.
        let request_data: CheckAndSetRequest = serde_json::from_slice(&body_bytes)
            .map_err(|e| worker::Error::RustError(format!("Invalid JSON: {}", e)))?;

        let nonce = &request_data.nonce;
        let ttl_seconds = request_data.ttl_seconds;

        // Perform check-and-set inline with state access
        let stored = self.check_and_set_internal(nonce, ttl_seconds).await?;

        if stored {
            Response::from_json(&serde_json::json!({
                "stored": true,
                "message": "Nonce stored successfully",
                "audit_events": serde_json::Value::Array(vec![])
            }))
        } else {
            // AL-097: Nonce replay detected. Embed audit event data in the
            // response so the worker-level caller can dispatch it via the
            // audit queue. Truncate the nonce value to 16 chars.
            let audit_event = HostedNonceDOAuditEvent {
                event_type: "nonce_replay_detected".to_string(),
                severity: Severity::Critical,
                event_category: EventCategory::SecurityEvent,
                outcome: "denied".to_string(),
                resource_id: nonce.get(..16).unwrap_or(nonce).to_string(),
                message: "Nonce replay attempt detected (already used)".to_string(),
                details: serde_json::json!({
                    "ttl_seconds": ttl_seconds,
                })
                .to_string(),
            };

            Ok(Response::from_json(&serde_json::json!({
                "stored": false,
                "message": "Nonce already used",
                "audit_events": [audit_event]
            }))?
            .with_status(409))
        }
    }

    /// SECURITY: Atomic check-and-set within the single-threaded DO runtime.
    /// The DO's single-writer guarantee prevents TOCTOU races: only one
    /// request can read-then-write at a time, so a nonce can never be
    /// accepted twice.
    async fn check_and_set_internal(&self, nonce: &str, ttl_seconds: u64) -> Result<bool> {
        let storage_key = format!("nonce:{}", nonce);

        // ADV-VA-03-002: Store and retrieve NonceRecord directly, not via
        // intermediate Vec<u8>. DO storage handles serialisation internally.
        let existing: Option<NonceRecord> = self
            .state
            .storage()
            .get::<NonceRecord>(&storage_key)
            .await
            .unwrap_or(None);

        if let Some(record) = existing {
            let now = Date::now().as_millis() / 1000;

            if record.expires_at >= now {
                return Ok(false);
            } else {
                let _ = self.state.storage().delete(&storage_key).await;
            }
        }

        let now = Date::now().as_millis() / 1000;

        let record = NonceRecord {
            nonce: nonce.to_string(),
            created_at: now,
            expires_at: now.saturating_add(ttl_seconds),
            used_by: None,
        };

        self.state
            .storage()
            .put(&storage_key, &record)
            .await
            .map_err(|e| worker::Error::RustError(format!("Failed to store nonce: {}", e)))?;

        Ok(true)
    }
}
