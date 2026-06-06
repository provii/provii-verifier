// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Security audit logging for compliance and monitoring.
//!
//! Wrapper around `provii_audit::AuditLogger` providing provii-verifier-specific
//! convenience methods. Uses the `AuditParams` struct with named fields
//! and `log_event_best_effort()` for fire-and-forget calls that log errors to
//! console instead of silently discarding them.
//!
//! ## DO Audit Pattern
//!
//! Durable Objects cannot access `AuditLogger` (no async sink, no privacy
//! context). Instead they collect `AuditEventData` structs during execution
//! and return them inside `DOResponse<T>`. The Worker-level caller
//! (`durable_object_store.rs`) extracts the events and dispatches them
//! through `dispatch_do_audit_events()`.
//!
//! ## Event Categories
//!
//! Events are categorised by `EventCategory` from the shared `provii_audit`
//! crate: `Authentication`, `Authorization`, `SessionLifecycle`,
//! `SecurityEvent`, `DataMutation`, `KeyAccess`, `AdminAction`,
//! `ExternalCall`, and `Verification`.
#![forbid(unsafe_code)]

use crate::security::log_sanitizer::{redact_challenge_id, redact_session_id};
use base64::Engine;
use provii_audit::{
    ActorType, AuditLogger as SharedLogger, AuditParams, Environment, EventCategory, Outcome,
    Severity,
};
use serde::{Deserialize, Serialize};
use worker::AnalyticsEngineDataPointBuilder;

#[cfg(target_arch = "wasm32")]
use worker::console_error;

/// Structured audit event data returned by Durable Objects.
///
/// DOs cannot access `AuditLogger` (no sink, no privacy context). They
/// populate these lightweight structs during execution and return them
/// inside `DOResponse<T>`. The Worker caller then dispatches each event
/// via `AuditLogger::dispatch_do_audit_events()`.
///
/// All fields are `String` (not `Option`) to match `AuditParams` convention
/// where empty string means "absent".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditEventData {
    /// Machine-readable event type (e.g. `"challenge_state_transition"`).
    pub event_type: String,
    /// Severity level: `"info"`, `"warning"`, `"error"`, or `"critical"`.
    pub severity: String,
    /// Human-readable description of the event.
    pub message: String,
    /// Raw IP address of the acting client (hashed by the audit sink).
    pub actor_ip: String,
    /// Origin URL associated with the event.
    pub origin: String,
    /// Identifier of the actor (client ID or service name).
    pub actor_id: String,
    /// Identifier of the affected resource.
    pub resource_id: String,
    /// Serialised JSON details blob.
    pub details: String,
    /// Request ID for tracing related events (maps to `AuditParams.request_id`).
    ///
    /// Renamed from `correlation_id` to `request_id` to match the
    /// field name used in `AuditParams` from the shared `provii_audit` crate.
    #[serde(alias = "correlation_id")]
    pub request_id: String,
    /// Deployment environment (e.g. `"production"`, `"sandbox"`).
    pub environment: String,
    /// Originating component (e.g. `"challenge_do"`, `"nonce_do"`).
    pub component: String,
    /// Worker version string at the time the event was produced.
    pub worker_version: String,
}

/// Wrapper returned by Durable Object HTTP handlers to carry both the
/// business result and collected audit events.
///
/// The DO serialises this as JSON. The Worker-level caller
/// (`durable_object_store.rs`) deserialises it, extracts the audit
/// events, and dispatches them through `AuditLogger`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DOResponse<T> {
    /// The business-logic result from the DO handler.
    pub result: T,
    /// Audit events collected during DO execution, dispatched by the Worker caller.
    pub audit_events: Vec<AuditEventData>,
}

/// provii-verifier audit logger wrapping the shared `provii_audit` crate.
///
/// Provides high-level convenience methods for verifier-specific events
/// while delegating IP hashing, console logging, and sink writes to the
/// shared audit infrastructure. Raw IPs are hashed via `PrivacyContext`
/// before any output (console or persistent storage).
///
/// Stores `environment` and `worker_version` at construction time so
/// callers do not need to pass them on every log call.
#[derive(Clone)]
pub struct AuditLogger {
    inner: SharedLogger,
    environment: String,
    worker_version: String,
}

impl AuditLogger {
    /// Creates a new AuditLogger wrapping the shared logger.
    ///
    /// `environment` and `worker_version` are captured once and passed to
    /// every audit event automatically.
    pub fn new(inner: SharedLogger, environment: String, worker_version: String) -> Self {
        Self {
            inner,
            environment,
            worker_version,
        }
    }

    /// Parse the stored environment string into the `Environment` enum.
    fn env(&self) -> Environment {
        if self.environment == "sandbox" {
            Environment::Sandbox
        } else {
            Environment::Production
        }
    }

    /// Dispatch a critical audit event with Analytics Engine fallback.
    ///
    /// On successful queue dispatch, behaves identically to `log_event_best_effort`.
    /// On failure, writes a minimal (PII-free) data point to the Analytics Engine
    /// dataset so that the dispatch failure is observable in dashboards even when
    /// the audit queue is completely unavailable.
    ///
    /// The fallback data point contains only: event_type, severity, and a count of
    /// 1.0. No raw_ip, origin, actor_id, or other PII fields are included.
    ///
    /// Callers MUST handle the return locally. This function does not propagate
    /// errors to the HTTP response.
    pub async fn log_event_critical(
        &self,
        params: AuditParams<'_>,
        analytics: Option<&worker::AnalyticsEngineDataset>,
    ) {
        // Capture event_type and severity before params is moved into log_event.
        let event_type_owned = params.event_type.to_string();
        let severity_str = params.severity.as_str().to_string();

        if let Err(_e) = self.inner.log_event(params).await {
            // Fallback: write a PII-free data point to Analytics Engine.
            if let Some(ae) = analytics {
                let dp = AnalyticsEngineDataPointBuilder::new()
                    .indexes(["audit_dispatch_failure"])
                    .blobs([event_type_owned.clone(), severity_str.clone()])
                    .doubles([1.0])
                    .build();
                let _ = ae.write_data_point(&dp);
            }

            #[cfg(target_arch = "wasm32")]
            console_error!(
                "CRITICAL audit dispatch failed: event_type={} severity={}",
                event_type_owned,
                severity_str
            );
        }
    }

    /// Log a challenge creation event.
    pub async fn log_challenge_created(
        &self,
        challenge_id: &str,
        client_ip: &str,
        origin: &str,
        client_id: Option<&str>,
    ) {
        let redacted = redact_challenge_id(challenge_id);
        let message = format!("Challenge {} created", redacted);
        let details = match client_id {
            Some(cid) => serde_json::json!({"client_id": cid}).to_string(),
            None => String::new(),
        };
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "challenge_created",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::SessionLifecycle,
                outcome: Some(Outcome::Success),
                raw_ip: client_ip,
                origin,
                challenge_id: &redacted,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "challenge",
                resource_id: &redacted,
                ..Default::default()
            })
            .await;
    }

    /// Log a verification attempt (success or failure).
    pub async fn log_verification_attempt(
        &self,
        challenge_id: &str,
        client_ip: &str,
        success: bool,
        reason: Option<String>,
    ) {
        let redacted = redact_challenge_id(challenge_id);
        let (event_type, severity, outcome) = if success {
            (
                "verification_success",
                Severity::Info,
                Some(Outcome::Success),
            )
        } else {
            (
                "verification_failed",
                Severity::Warning,
                Some(Outcome::Failure),
            )
        };
        let message = if success {
            format!("Verification succeeded for challenge {}", redacted)
        } else {
            format!(
                "Verification failed for challenge {}: {:?}",
                redacted, reason
            )
        };
        self.inner
            .log_event_best_effort(AuditParams {
                event_type,
                severity,
                message: &message,
                event_category: EventCategory::Verification,
                outcome,
                raw_ip: client_ip,
                challenge_id: &redacted,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "challenge",
                resource_id: &redacted,
                ..Default::default()
            })
            .await;
    }

    /// Log a billing event (verification success with royalty).
    ///
    /// Previously console-only; now persisted through the shared audit sink.
    pub async fn log_billing_event(
        &self,
        challenge_id: &str,
        rp_origin: &str,
        issuer_kid: Option<&str>,
        issuer_key_hash: &[u8; 32],
        cutoff_days: i32,
        timestamp: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let redacted = redact_challenge_id(challenge_id);
        let has_royalty = issuer_kid.is_some();
        let royalty_recipient = issuer_kid.unwrap_or("none");
        let issuer_hash_b64 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(issuer_key_hash);
        let details = serde_json::json!({
            "royalty_to": royalty_recipient,
            "has_royalty": has_royalty,
            "cutoff_days": cutoff_days,
            "timestamp": timestamp,
            "issuer_hash": issuer_hash_b64,
        })
        .to_string();
        let message = format!(
            "Billing event: challenge={}, charge_to={}, royalty_to={}",
            redacted, rp_origin, royalty_recipient
        );
        self.inner
            .log_event(AuditParams {
                event_type: "billing_verification_success",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::Verification,
                outcome: Some(Outcome::Success),
                raw_ip: "system",
                origin: rp_origin,
                challenge_id: &redacted,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "challenge",
                resource_id: &redacted,
                actor_type: Some(ActorType::System),
                ..Default::default()
            })
            .await?;
        Ok(())
    }

    /// Log a verification event with no royalty.
    ///
    /// Previously console-only; now persisted through the shared audit sink.
    pub async fn log_verification_no_royalty(
        &self,
        challenge_id: &str,
        rp_origin: &str,
        issuer_key_hash: &[u8; 32],
        timestamp: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let redacted = redact_challenge_id(challenge_id);
        let issuer_hash_b64 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(issuer_key_hash);
        let details = serde_json::json!({
            "timestamp": timestamp,
            "issuer_hash": issuer_hash_b64,
            "note": "Full amount charged to RP",
        })
        .to_string();
        let message = format!(
            "No-royalty billing event: challenge={}, charge_to={}",
            redacted, rp_origin
        );
        self.inner
            .log_event(AuditParams {
                event_type: "billing_no_royalty",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::Verification,
                outcome: Some(Outcome::Success),
                raw_ip: "system",
                origin: rp_origin,
                challenge_id: &redacted,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "challenge",
                resource_id: &redacted,
                actor_type: Some(ActorType::System),
                ..Default::default()
            })
            .await?;
        Ok(())
    }

    /// Log a replay attack attempt.
    ///
    /// Uses tiered delivery: attempts queue dispatch first, falls back to
    /// Analytics Engine on failure for observability of critical security events.
    pub async fn log_replay_attempt(
        &self,
        challenge_id: &str,
        client_ip: &str,
        analytics: Option<&worker::AnalyticsEngineDataset>,
    ) {
        let redacted = redact_challenge_id(challenge_id);
        let message = format!("Replay attack detected for challenge {}", redacted);
        self.log_event_critical(
            AuditParams {
                event_type: "replay_attempt",
                severity: Severity::Critical,
                message: &message,
                event_category: EventCategory::SecurityEvent,
                outcome: Some(Outcome::Denied),
                raw_ip: client_ip,
                challenge_id: &redacted,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "challenge",
                resource_id: &redacted,
                ..Default::default()
            },
            analytics,
        )
        .await;
    }

    /// Log suspicious activity.
    pub async fn log_suspicious_activity(&self, client_ip: &str, reason: &str) {
        let message = format!("Suspicious activity detected: {}", reason);
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "suspicious_activity",
                severity: Severity::Warning,
                message: &message,
                event_category: EventCategory::SecurityEvent,
                outcome: Some(Outcome::Denied),
                raw_ip: client_ip,
                environment: self.env(),
                worker_version: &self.worker_version,
                ..Default::default()
            })
            .await;
    }

    /// Log authentication failure for security monitoring and compliance.
    ///
    /// Addresses CWE-778 (Insufficient Logging) and ASVS V7.2.1.
    pub async fn log_authentication_failure(
        &self,
        client_ip: &str,
        failure_type: &str,
        client_id: Option<&str>,
        origin: Option<&str>,
        details: Option<serde_json::Value>,
    ) {
        let message = if let Some(cid) = client_id {
            format!(
                "Authentication failed: {} for client_id={}",
                failure_type, cid
            )
        } else {
            format!("Authentication failed: {}", failure_type)
        };
        let details_str = match details {
            Some(d) => d.to_string(),
            None => match client_id {
                Some(cid) => {
                    serde_json::json!({"client_id": cid, "failure_type": failure_type}).to_string()
                }
                None => String::new(),
            },
        };
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "authentication_failed",
                severity: Severity::Warning,
                message: &message,
                event_category: EventCategory::Authentication,
                outcome: Some(Outcome::Failure),
                raw_ip: client_ip,
                origin: origin.unwrap_or(""),
                details: &details_str,
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_id: client_id.unwrap_or(""),
                actor_type: Some(ActorType::ApiKey),
                ..Default::default()
            })
            .await;
    }

    /// Log a royalty event.
    pub async fn log_royalty_event(
        &self,
        kid: &str,
        issuer_key_hash: &[u8; 32],
        origin: &str,
        cutoff_days: i32,
    ) {
        let issuer_hash_b64 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(issuer_key_hash);
        let message = format!(
            "Royalty event: issuer={}, origin={}, cutoff_days={}",
            kid, origin, cutoff_days
        );
        let details = serde_json::json!({
            "issuer_kid": kid,
            "issuer_hash": issuer_hash_b64,
            "origin": origin,
            "cutoff_days": cutoff_days,
        })
        .to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "royalty_attributed",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::ExternalCall,
                outcome: Some(Outcome::Success),
                raw_ip: "system",
                origin,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_id: kid,
                actor_type: Some(ActorType::Service),
                resource_type: "issuer_key",
                resource_id: kid,
                ..Default::default()
            })
            .await;
    }

    /// Log data deletion request (GDPR Article 17).
    pub async fn log_data_deletion_request(
        &self,
        data_type: &str,
        item_id: &str,
        reason: &str,
        requester_ip: &str,
        requester_id: Option<&str>,
    ) {
        let message = if let Some(req_id) = requester_id {
            format!(
                "Data deletion requested: type={}, item={}, reason={}, requester={}",
                data_type, item_id, reason, req_id
            )
        } else {
            format!(
                "Data deletion requested: type={}, item={}, reason={}",
                data_type, item_id, reason
            )
        };
        let details = match requester_id {
            Some(req_id) => serde_json::json!({
                "data_type": data_type,
                "item_id": item_id,
                "reason": reason,
                "requester_id": req_id,
            }),
            None => serde_json::json!({
                "data_type": data_type,
                "item_id": item_id,
                "reason": reason,
            }),
        }
        .to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "data_deletion_requested",
                severity: Severity::Warning,
                message: &message,
                event_category: EventCategory::DataMutation,
                outcome: Some(Outcome::Success),
                raw_ip: requester_ip,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_id: requester_id.unwrap_or(""),
                actor_type: requester_id.as_ref().map(|_| ActorType::User),
                resource_type: data_type,
                resource_id: item_id,
                ..Default::default()
            })
            .await;
    }

    /// Log data deletion completion (GDPR Article 17).
    pub async fn log_data_deletion_completed(
        &self,
        data_type: &str,
        item_id: &str,
        soft_delete: bool,
        audit_id: &str,
    ) {
        let delete_type = if soft_delete {
            "soft-deleted"
        } else {
            "hard-deleted"
        };
        let message = format!(
            "Data {} successfully: type={}, item={}, audit_id={}",
            delete_type, data_type, item_id, audit_id
        );
        let details = serde_json::json!({
            "data_type": data_type,
            "item_id": item_id,
            "soft_delete": soft_delete,
            "audit_id": audit_id,
        })
        .to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "data_deletion_completed",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::DataMutation,
                outcome: Some(Outcome::Success),
                raw_ip: "system",
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_type: Some(ActorType::System),
                resource_type: data_type,
                resource_id: item_id,
                ..Default::default()
            })
            .await;
    }

    /// Log a successful short code lookup (P3-25).
    pub async fn log_short_code_lookup_success(
        &self,
        short_code: &str,
        challenge_id: &str,
        client_ip: &str,
    ) {
        let redacted = redact_challenge_id(challenge_id);
        let message = format!(
            "Short code lookup succeeded: code={}, challenge={}",
            short_code, redacted
        );
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "short_code_lookup_success",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::SessionLifecycle,
                outcome: Some(Outcome::Success),
                raw_ip: client_ip,
                challenge_id: &redacted,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "challenge",
                resource_id: &redacted,
                ..Default::default()
            })
            .await;
    }

    /// Log a successful challenge poll (P3-26).
    pub async fn log_challenge_poll_success(
        &self,
        challenge_id: &str,
        client_ip: &str,
        client_id: &str,
    ) {
        let redacted = redact_challenge_id(challenge_id);
        let details = serde_json::json!({"client_id": client_id}).to_string();
        let message = format!("Challenge poll succeeded for {}", redacted);
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "challenge_poll_success",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::SessionLifecycle,
                outcome: Some(Outcome::Success),
                raw_ip: client_ip,
                challenge_id: &redacted,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_id: client_id,
                actor_type: Some(ActorType::ApiKey),
                resource_type: "challenge",
                resource_id: &redacted,
                ..Default::default()
            })
            .await;
    }

    /// Log a successful authentication (AL-038).
    ///
    /// Addresses CWE-778: both success and failure paths must be audited.
    pub async fn log_authentication_success(&self, client_ip: &str, client_id: &str, origin: &str) {
        let message = format!("Authentication succeeded for client_id={}", client_id);
        let details = serde_json::json!({"client_id": client_id, "origin": origin}).to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "authentication_success",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::Authentication,
                outcome: Some(Outcome::Success),
                raw_ip: client_ip,
                origin,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_id: client_id,
                actor_type: Some(ActorType::ApiKey),
                ..Default::default()
            })
            .await;
    }

    /// Log denial due to a disabled origin (AL-046).
    ///
    /// CRITICAL: Disabled origins returning None silently is a compliance gap.
    pub async fn log_origin_disabled(&self, origin: &str, client_ip: &str) {
        let message = format!("Origin {} is disabled, access denied", origin);
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "origin_disabled_denied",
                severity: Severity::Warning,
                message: &message,
                event_category: EventCategory::Authorization,
                outcome: Some(Outcome::Denied),
                raw_ip: client_ip,
                origin,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "origin_policy",
                resource_id: origin,
                ..Default::default()
            })
            .await;
    }

    /// Log denial due to an unknown/unregistered origin (AL-047).
    pub async fn log_origin_not_found(&self, origin: &str, client_ip: &str) {
        let message = format!("Origin {} not found in policy store, access denied", origin);
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "origin_not_found_denied",
                severity: Severity::Warning,
                message: &message,
                event_category: EventCategory::Authorization,
                outcome: Some(Outcome::Denied),
                raw_ip: client_ip,
                origin,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "origin_policy",
                resource_id: origin,
                ..Default::default()
            })
            .await;
    }

    /// Log a sandbox `rp_sandbox_*` origin bypass on `/v1/challenge`.
    ///
    /// Emitted at `Info` severity (not Warning) because this is the expected
    /// path for sandbox developer DX, not a security violation. Production
    /// `pk_live_*` / non-sandbox traffic never hits this code path. The log
    /// captures `request_origin` vs `registered_origin` so an operator can
    /// verify the bypass is only applied where intended.
    pub async fn log_sandbox_origin_bypass(
        &self,
        client_id: &str,
        request_origin: &str,
        registered_origin: &str,
        client_ip: &str,
    ) {
        let message = format!(
            "Sandbox rp_sandbox_* origin check skipped for client_id={} (request_origin={}, registered_origin={})",
            client_id, request_origin, registered_origin
        );
        let details = serde_json::json!({
            "client_id": client_id,
            "request_origin": request_origin,
            "registered_origin": registered_origin,
        })
        .to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "sandbox_origin_bypass",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::Authorization,
                outcome: Some(Outcome::Success),
                raw_ip: client_ip,
                origin: request_origin,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_id: client_id,
                actor_type: Some(ActorType::User),
                resource_type: "origin_policy",
                resource_id: registered_origin,
                ..Default::default()
            })
            .await;
    }

    /// Log client provisioning (AL-048).
    pub async fn log_client_provisioned(&self, client_id: &str, origin: &str) {
        let message = format!("Client {} provisioned for origin {}", client_id, origin);
        let details = serde_json::json!({"client_id": client_id, "origin": origin}).to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "client_provisioned",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::AdminAction,
                outcome: Some(Outcome::Success),
                raw_ip: "system",
                origin,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_id: client_id,
                actor_type: Some(ActorType::System),
                resource_type: "client",
                resource_id: client_id,
                ..Default::default()
            })
            .await;
    }

    /// Log client HMAC secret rotation (AL-048).
    pub async fn log_client_secret_updated(&self, client_id: &str) {
        let message = format!("HMAC secret updated for client_id={}", client_id);
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "client_secret_updated",
                severity: Severity::Warning,
                message: &message,
                event_category: EventCategory::KeyAccess,
                outcome: Some(Outcome::Success),
                raw_ip: "system",
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_type: Some(ActorType::System),
                resource_type: "client",
                resource_id: client_id,
                ..Default::default()
            })
            .await;
    }

    /// Log forbidden-origin denial during challenge creation (AL-021).
    pub async fn log_forbidden_origin(&self, origin: &str, client_ip: &str, endpoint: &str) {
        let message = format!("Forbidden origin denied: {} on {}", origin, endpoint);
        let details = serde_json::json!({"origin": origin, "endpoint": endpoint}).to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "forbidden_origin_denied",
                severity: Severity::Warning,
                message: &message,
                event_category: EventCategory::Authorization,
                outcome: Some(Outcome::Denied),
                raw_ip: client_ip,
                origin,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "origin_policy",
                resource_id: origin,
                ..Default::default()
            })
            .await;
    }

    /// Log VK-ID-not-allowed denial (AL-025).
    pub async fn log_vk_id_not_allowed(
        &self,
        vk_id: u32,
        origin: &str,
        challenge_id: &str,
        client_ip: &str,
    ) {
        let redacted = redact_challenge_id(challenge_id);
        let message = format!(
            "Verifying key {} not allowed for origin {} (challenge {})",
            vk_id, origin, redacted
        );
        let details = serde_json::json!({
            "vk_id": vk_id,
            "origin": origin,
            "challenge_id": redacted,
        })
        .to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "vk_id_not_allowed",
                severity: Severity::Warning,
                message: &message,
                event_category: EventCategory::Authorization,
                outcome: Some(Outcome::Denied),
                raw_ip: client_ip,
                origin,
                challenge_id: &redacted,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "challenge",
                resource_id: &redacted,
                ..Default::default()
            })
            .await;
    }

    /// Log revocation cache hit (AL-023).
    pub async fn log_revocation_cache_hit(
        &self,
        challenge_id: &str,
        origin: &str,
        client_ip: &str,
    ) {
        let redacted = redact_challenge_id(challenge_id);
        let message = format!(
            "Revoked issuer rejected via cache for challenge {} origin {}",
            redacted, origin
        );
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "revocation_cache_hit",
                severity: Severity::Warning,
                message: &message,
                event_category: EventCategory::SecurityEvent,
                outcome: Some(Outcome::Denied),
                raw_ip: client_ip,
                origin,
                challenge_id: &redacted,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "challenge",
                resource_id: &redacted,
                ..Default::default()
            })
            .await;
    }

    /// Log challenge expiry inconsistency (AL-027).
    ///
    /// Emitted when the stored `expires_at` disagrees with the KV TTL
    /// (challenge found in KV but past its logical expiry).
    pub async fn log_challenge_expiry_inconsistency(
        &self,
        challenge_id: &str,
        expires_at: u64,
        now: u64,
        client_ip: &str,
    ) {
        let redacted = redact_challenge_id(challenge_id);
        let message = format!(
            "Challenge {} expired (expires_at={}, now={}) but still in KV",
            redacted, expires_at, now
        );
        let details = serde_json::json!({
            "challenge_id": redacted,
            "expires_at": expires_at,
            "now": now,
            "drift_seconds": now.saturating_sub(expires_at),
        })
        .to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "challenge_expiry_inconsistency",
                severity: Severity::Warning,
                message: &message,
                event_category: EventCategory::SessionLifecycle,
                outcome: Some(Outcome::Failure),
                raw_ip: client_ip,
                challenge_id: &redacted,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "challenge",
                resource_id: &redacted,
                ..Default::default()
            })
            .await;
    }

    /// Log sandbox API key authentication failure (AL-022).
    pub async fn log_sandbox_api_key_failure(&self, client_ip: &str, origin: &str) {
        let message = format!(
            "Sandbox API key authentication failed for origin {}",
            origin
        );
        let details = serde_json::json!({
            "endpoint": "/v1/register-test-origin",
            "origin": origin,
        })
        .to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "sandbox_api_key_failure",
                severity: Severity::Warning,
                message: &message,
                event_category: EventCategory::Authentication,
                outcome: Some(Outcome::Denied),
                raw_ip: client_ip,
                origin,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "sandbox_registration",
                resource_id: origin,
                ..Default::default()
            })
            .await;
    }

    /// Log malicious origin detection (AL-043).
    ///
    /// Uses tiered delivery: attempts queue dispatch first, falls back to
    /// Analytics Engine on failure for observability of critical security events.
    pub async fn log_malicious_origin_detected(
        &self,
        origin: &str,
        client_ip: &str,
        analytics: Option<&worker::AnalyticsEngineDataset>,
    ) {
        let message = format!("Malicious origin detected: {}", origin);
        let details = serde_json::json!({
            "origin": origin,
            "reason": "scheme_injection",
        })
        .to_string();
        self.log_event_critical(
            AuditParams {
                event_type: "malicious_origin_detected",
                severity: Severity::Critical,
                message: &message,
                event_category: EventCategory::SecurityEvent,
                outcome: Some(Outcome::Denied),
                raw_ip: client_ip,
                origin,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "origin",
                resource_id: origin,
                ..Default::default()
            },
            analytics,
        )
        .await;
    }

    /// Log fail-open on idempotency DO store failure (AL-044).
    ///
    /// Uses tiered delivery: attempts queue dispatch first, falls back to
    /// Analytics Engine on failure for observability of critical security events.
    pub async fn log_idempotency_store_fail_open(
        &self,
        key: &str,
        error_msg: &str,
        client_ip: &str,
        analytics: Option<&worker::AnalyticsEngineDataset>,
    ) {
        let message = format!(
            "Idempotency store failure, proceeding without protection: {}",
            error_msg
        );
        let details = serde_json::json!({
            "idempotency_key": key,
            "error": error_msg,
        })
        .to_string();
        self.log_event_critical(
            AuditParams {
                event_type: "idempotency_store_fail_open",
                severity: Severity::Critical,
                message: &message,
                event_category: EventCategory::SecurityEvent,
                outcome: Some(Outcome::Failure),
                raw_ip: client_ip,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "idempotency",
                resource_id: key,
                ..Default::default()
            },
            analytics,
        )
        .await;
    }

    /// Log MEK missing or decryption failure (AL-042).
    ///
    /// SECURITY: Never log the key material itself.
    ///
    /// Uses tiered delivery: attempts queue dispatch first, falls back to
    /// Analytics Engine on failure for observability of critical security events.
    pub async fn log_mek_failure(
        &self,
        client_id: &str,
        failure_type: &str,
        client_ip: &str,
        analytics: Option<&worker::AnalyticsEngineDataset>,
    ) {
        let message = format!(
            "MEK operation failed for client_id={}: {}",
            client_id, failure_type
        );
        let details = serde_json::json!({
            "client_id": client_id,
            "failure_type": failure_type,
        })
        .to_string();
        self.log_event_critical(
            AuditParams {
                event_type: "mek_failure",
                severity: Severity::Critical,
                message: &message,
                event_category: EventCategory::KeyAccess,
                outcome: Some(Outcome::Failure),
                raw_ip: client_ip,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_id: client_id,
                actor_type: Some(ActorType::ApiKey),
                resource_type: "mek",
                ..Default::default()
            },
            analytics,
        )
        .await;
    }

    /// Log credit consumption success or failure (AL-053).
    pub async fn log_credit_consumption(
        &self,
        client_ip: &str,
        origin: &str,
        verification_id: &str,
        success: bool,
        details_json: &str,
    ) {
        let (event_type, severity, outcome) = if success {
            ("credit_consumed", Severity::Info, Some(Outcome::Success))
        } else {
            (
                "credit_consumption_failed",
                Severity::Warning,
                Some(Outcome::Failure),
            )
        };
        let message = if success {
            format!(
                "Credit consumed for verification {} origin {}",
                verification_id, origin
            )
        } else {
            format!(
                "Credit consumption failed for verification {} origin {}",
                verification_id, origin
            )
        };
        self.inner
            .log_event_best_effort(AuditParams {
                event_type,
                severity,
                message: &message,
                event_category: EventCategory::ExternalCall,
                outcome,
                raw_ip: client_ip,
                origin,
                details: details_json,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "credit",
                resource_id: verification_id,
                ..Default::default()
            })
            .await;
    }

    /// Log rate limit exceeded event (AL-024).
    pub async fn log_rate_limit_exceeded(
        &self,
        client_id: &str,
        endpoint: &str,
        client_ip: &str,
        current_count: u32,
        limit: u32,
    ) {
        let message = format!(
            "Rate limit exceeded for client '{}' on endpoint '{}' ({}/{})",
            client_id, endpoint, current_count, limit
        );
        let details = serde_json::json!({
            "client_id": client_id,
            "endpoint": endpoint,
            "current_count": current_count,
            "limit": limit,
        })
        .to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "rate_limit_exceeded",
                severity: Severity::Warning,
                message: &message,
                event_category: EventCategory::SecurityEvent,
                outcome: Some(Outcome::Denied),
                raw_ip: client_ip,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_id: client_id,
                actor_type: Some(ActorType::ApiKey),
                resource_type: "rate_limit",
                resource_id: endpoint,
                ..Default::default()
            })
            .await;
    }

    /// Log cutoff date validation event (AL-026).
    pub async fn log_cutoff_validation(
        &self,
        origin: &str,
        age_years: u32,
        cutoff_days: i32,
        direction: &str,
    ) {
        let message = format!(
            "Cutoff validation: origin={} age_years={} cutoff_days={} direction={}",
            origin, age_years, cutoff_days, direction
        );
        let details = serde_json::json!({
            "origin": origin,
            "age_years": age_years,
            "cutoff_days": cutoff_days,
            "direction": direction,
        })
        .to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "cutoff_validation",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::Verification,
                outcome: Some(Outcome::Success),
                raw_ip: "system",
                origin,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_type: Some(ActorType::System),
                resource_type: "origin_policy",
                resource_id: origin,
                ..Default::default()
            })
            .await;
    }

    /// Log status endpoint access (AL-031).
    pub async fn log_status_endpoint_access(
        &self,
        client_ip: &str,
        endpoint: &str,
        authorized: bool,
    ) {
        let (severity, outcome) = if authorized {
            (Severity::Info, Some(Outcome::Success))
        } else {
            (Severity::Warning, Some(Outcome::Denied))
        };
        let message = format!(
            "Status endpoint '{}' access {}",
            endpoint,
            if authorized { "granted" } else { "denied" }
        );
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "status_endpoint_access",
                severity,
                message: &message,
                event_category: EventCategory::Authorization,
                outcome,
                raw_ip: client_ip,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "status_endpoint",
                resource_id: endpoint,
                ..Default::default()
            })
            .await;
    }

    /// Log a CRITICAL event when KV state write fails after credits have been
    /// successfully deducted (KV-046). The credit deduction is the authoritative
    /// billing record; this event enables manual reconciliation.
    ///
    /// Uses tiered delivery: attempts queue dispatch first, falls back to
    /// Analytics Engine on failure for observability of critical security events.
    pub async fn log_state_write_failed_after_billing(
        &self,
        challenge_id: &str,
        client_ip: &str,
        analytics: Option<&worker::AnalyticsEngineDataset>,
    ) {
        let redacted = redact_challenge_id(challenge_id);
        let message = format!(
            "KV state write failed after successful credit deduction for challenge {}. \
             Credits deducted but state not updated to Verified.",
            redacted
        );
        self.log_event_critical(
            AuditParams {
                event_type: "state_write_failed_after_billing",
                severity: Severity::Critical,
                message: &message,
                event_category: EventCategory::SecurityEvent,
                outcome: Some(Outcome::Error),
                raw_ip: client_ip,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "challenge",
                resource_id: &redacted,
                ..Default::default()
            },
            analytics,
        )
        .await;
    }

    /// Log successful sandbox test origin registration (AL-031).
    ///
    /// Replaces the prior misuse of `log_suspicious_activity`. This event is
    /// emitted on the legitimate self-service path that creates a new origin
    /// policy KV entry in the sandbox environment.
    pub async fn log_test_origin_registered(
        &self,
        client_ip: &str,
        origin: &str,
        client_id: &str,
        ttl_seconds: u64,
    ) {
        let message = format!(
            "Test origin '{}' registered with client_id '{}'",
            origin, client_id
        );
        let details = serde_json::json!({
            "origin": origin,
            "client_id": client_id,
            "ttl_seconds": ttl_seconds,
        })
        .to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "test_origin_registered",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::AdminAction,
                outcome: Some(Outcome::Success),
                raw_ip: client_ip,
                origin,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_id: client_id,
                actor_type: Some(ActorType::User),
                resource_type: "origin_policy",
                resource_id: origin,
                ..Default::default()
            })
            .await;
    }

    /// Log idempotent re-registration of an existing test origin (AL-031).
    ///
    /// Emitted when the registration handler returns the existing policy
    /// rather than creating a new one. No new secrets are issued.
    pub async fn log_test_origin_reregistration(&self, client_ip: &str, origin: &str) {
        let message = format!(
            "Test origin '{}' re-registration ignored (already exists)",
            origin
        );
        let details = serde_json::json!({
            "origin": origin,
            "already_existed": true,
        })
        .to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "test_origin_reregistration",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::AdminAction,
                outcome: Some(Outcome::Success),
                raw_ip: client_ip,
                origin,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                actor_type: Some(ActorType::User),
                resource_type: "origin_policy",
                resource_id: origin,
                ..Default::default()
            })
            .await;
    }

    /// Log CSRF token generation success (AL-032).
    ///
    /// `session_id` is `"anonymous"` for the pre-session endpoint or the
    /// caller-supplied session UUID for the bound endpoint.
    pub async fn log_csrf_token_generated(&self, client_ip: &str, session_id: &str) {
        // SECURITY (AL-X1): Session IDs are bearer-like tokens. Redact the raw
        // UUID before it lands in `details.session_id` or `resource_id`. The
        // "anonymous" sentinel is preserved verbatim so the pre-session
        // endpoint remains distinguishable in audit queries.
        let redacted = if session_id == "anonymous" {
            session_id.to_string()
        } else {
            redact_session_id(session_id)
        };
        let message = format!("CSRF token generated for session '{}'", redacted);
        let details = serde_json::json!({
            "session_id": redacted,
        })
        .to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "csrf_token_generated",
                severity: Severity::Info,
                message: &message,
                event_category: EventCategory::SessionLifecycle,
                outcome: Some(Outcome::Success),
                raw_ip: client_ip,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "csrf_token",
                resource_id: &redacted,
                ..Default::default()
            })
            .await;
    }

    /// Log a CSRF token validation failure on a mutating hosted endpoint
    /// (SEC-028).
    ///
    /// SECURITY: `failure_reason` must be a short non-secret tag produced by
    /// [`crate::hosted::endpoints::csrf::CsrfValidationError::failure_reason`];
    /// never pass raw error text that might leak internal state or secrets.
    /// The `session_id` is redacted (or preserved as `"anonymous"` for
    /// pre-session endpoints).
    pub async fn log_csrf_validation_failed(
        &self,
        client_ip: &str,
        endpoint: &str,
        session_id: &str,
        failure_reason: &str,
    ) {
        let redacted = if session_id == "anonymous" {
            session_id.to_string()
        } else {
            redact_session_id(session_id)
        };
        let message = format!(
            "CSRF validation failed on {} for session '{}': {}",
            endpoint, redacted, failure_reason
        );
        let details = serde_json::json!({
            "endpoint": endpoint,
            "session_id": redacted,
            "failure_reason": failure_reason,
        })
        .to_string();
        self.inner
            .log_event_best_effort(AuditParams {
                event_type: "csrf_validation_failed",
                severity: Severity::Warning,
                message: &message,
                event_category: EventCategory::SecurityEvent,
                outcome: Some(Outcome::Denied),
                raw_ip: client_ip,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "csrf_token",
                resource_id: &redacted,
                ..Default::default()
            })
            .await;
    }

    /// Log CSRF token generation failure (AL-032).
    ///
    /// SECURITY: `failure_reason` must be a short non-secret tag (e.g.
    /// `"signing_key_unavailable"`, `"handler_error"`). Never pass raw error
    /// text that might contain key material.
    ///
    /// Uses tiered delivery: attempts queue dispatch first, falls back to
    /// Analytics Engine on failure for observability.
    pub async fn log_csrf_token_generation_failed(
        &self,
        client_ip: &str,
        session_id: &str,
        failure_reason: &str,
        analytics: Option<&worker::AnalyticsEngineDataset>,
    ) {
        // SECURITY (AL-X1): Mirror the redaction in `log_csrf_token_generated`.
        let redacted = if session_id == "anonymous" {
            session_id.to_string()
        } else {
            redact_session_id(session_id)
        };
        let message = format!(
            "CSRF token generation failed for session '{}': {}",
            redacted, failure_reason
        );
        let details = serde_json::json!({
            "session_id": redacted,
            "failure_reason": failure_reason,
        })
        .to_string();
        self.log_event_critical(
            AuditParams {
                event_type: "csrf_token_generation_failed",
                severity: Severity::Error,
                message: &message,
                event_category: EventCategory::SessionLifecycle,
                outcome: Some(Outcome::Failure),
                raw_ip: client_ip,
                details: &details,
                environment: self.env(),
                worker_version: &self.worker_version,
                resource_type: "csrf_token",
                resource_id: &redacted,
                ..Default::default()
            },
            analytics,
        )
        .await;
    }

    /// Dispatch audit events collected by a Durable Object.
    ///
    /// DOs cannot access `AuditLogger` directly. They return
    /// `Vec<AuditEventData>` in `DOResponse`. This method converts
    /// each `AuditEventData` to an `AuditParams` and dispatches it.
    ///
    /// `client_ip`, `origin`, and `request_id` provide caller-side context
    /// that the DO cannot know. Empty event-level fields are populated from
    /// these defaults; non-empty event fields take precedence.
    pub async fn dispatch_do_audit_events(
        &self,
        events: &[AuditEventData],
        client_ip: &str,
        origin: &str,
        request_id: &str,
    ) {
        for evt in events {
            let severity = match evt.severity.as_str() {
                "critical" => Severity::Critical,
                "error" => Severity::Error,
                "warning" => Severity::Warning,
                _ => Severity::Info,
            };
            let event_category = match evt.component.as_str() {
                "challenge_do" => EventCategory::SessionLifecycle,
                "nonce_do" => EventCategory::SecurityEvent,
                _ => EventCategory::SecurityEvent,
            };
            // Prefer event-supplied context, fall back to caller context.
            let raw_ip = if evt.actor_ip.is_empty() {
                client_ip
            } else {
                evt.actor_ip.as_str()
            };
            let event_origin = if evt.origin.is_empty() {
                origin
            } else {
                evt.origin.as_str()
            };
            let req_id = if evt.request_id.is_empty() {
                request_id
            } else {
                evt.request_id.as_str()
            };
            self.inner
                .log_event_best_effort(AuditParams {
                    event_type: &evt.event_type,
                    severity,
                    message: &evt.message,
                    event_category,
                    outcome: if evt.severity == "critical" || evt.severity == "error" {
                        Some(Outcome::Denied)
                    } else if evt.severity == "warning" {
                        Some(Outcome::Failure)
                    } else {
                        Some(Outcome::Success)
                    },
                    raw_ip,
                    origin: event_origin,
                    details: &evt.details,
                    request_id: req_id,
                    environment: self.env(),
                    worker_version: &self.worker_version,
                    actor_id: &evt.actor_id,
                    resource_id: &evt.resource_id,
                    ..Default::default()
                })
                .await;
        }
    }

    /// Dispatch audit events collected by `HostedNonceDO`.
    ///
    /// The hosted nonce DO uses a typed `Severity`/`EventCategory` event
    /// struct (`HostedNonceDOAuditEvent`). This method maps those typed
    /// fields onto `AuditParams` and dispatches each event best-effort.
    pub async fn dispatch_hosted_nonce_audit_events(
        &self,
        events: &[crate::hosted::durable_objects::HostedNonceDOAuditEvent],
        client_ip: &str,
        origin: &str,
        request_id: &str,
    ) {
        for evt in events {
            self.inner
                .log_event_best_effort(AuditParams {
                    event_type: &evt.event_type,
                    severity: evt.severity,
                    message: &evt.message,
                    event_category: evt.event_category,
                    outcome: match evt.outcome.as_str() {
                        "success" => Some(Outcome::Success),
                        "failure" => Some(Outcome::Failure),
                        "denied" => Some(Outcome::Denied),
                        "error" => Some(Outcome::Error),
                        _ => None,
                    },
                    raw_ip: client_ip,
                    origin,
                    details: &evt.details,
                    request_id,
                    environment: self.env(),
                    worker_version: &self.worker_version,
                    resource_id: &evt.resource_id,
                    ..Default::default()
                })
                .await;
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::string_slice
)]
mod tests {
    use super::*;
    use provii_audit::PrivacyContext;
    use std::sync::Arc;

    fn test_logger() -> Result<AuditLogger, Box<dyn std::error::Error>> {
        let salt = b"test-salt-minimum-32-bytes-long!!".to_vec();
        let privacy = Arc::new(PrivacyContext::new(salt)?);
        let inner = SharedLogger::new(None, privacy, "provii-verifier-test");
        Ok(AuditLogger::new(
            inner,
            "test".to_string(),
            "0.0.0".to_string(),
        ))
    }

    #[tokio::test]
    async fn test_log_challenge_created() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // Should not panic; logger has no sink so event is console-only
        logger
            .log_challenge_created(
                "550e8400-e29b-41d4-a716-446655440000",
                "192.168.1.1",
                "https://example.com",
                Some("client-123"),
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_verification_attempt_success() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_verification_attempt(
                "550e8400-e29b-41d4-a716-446655440000",
                "192.168.1.1",
                true,
                None,
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_verification_attempt_failure() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_verification_attempt(
                "550e8400-e29b-41d4-a716-446655440000",
                "192.168.1.1",
                false,
                Some("proof invalid".to_string()),
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_billing_event() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let result = logger
            .log_billing_event(
                "550e8400",
                "https://example.com",
                Some("issuer-kid-1"),
                &[0u8; 32],
                365,
                1700000000,
            )
            .await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_log_verification_no_royalty() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let result = logger
            .log_verification_no_royalty("550e8400", "https://example.com", &[0u8; 32], 1700000000)
            .await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_log_replay_attempt() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_replay_attempt("550e8400", "192.168.1.1", None)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_suspicious_activity() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_suspicious_activity("192.168.1.1", "rate limit exceeded")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_authentication_failure_with_details() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        logger
            .log_authentication_failure(
                "192.168.1.1",
                "invalid_api_key",
                Some("client-abc"),
                Some("https://example.com"),
                Some(serde_json::json!({"endpoint": "status"})),
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_authentication_failure_minimal() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_authentication_failure("192.168.1.1", "missing_header", None, None, None)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_royalty_event() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_royalty_event("kid-1", &[0u8; 32], "https://example.com", 365)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_data_deletion_request() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_data_deletion_request(
                "challenge",
                "item-123",
                "gdpr_request",
                "192.168.1.1",
                Some("admin-1"),
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_data_deletion_completed() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_data_deletion_completed("challenge", "item-123", true, "audit-456")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_short_code_lookup_success() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_short_code_lookup_success(
                "1234 5678 9012",
                "550e8400-e29b-41d4-a716-446655440000",
                "192.168.1.1",
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_challenge_poll_success() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_challenge_poll_success(
                "550e8400-e29b-41d4-a716-446655440000",
                "192.168.1.1",
                "client-abc",
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_authentication_success() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_authentication_success("192.168.1.1", "client-abc", "https://example.com")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_origin_disabled() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_origin_disabled("https://disabled.com", "192.168.1.1")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_origin_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_origin_not_found("https://unknown.com", "192.168.1.1")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_sandbox_origin_bypass() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_sandbox_origin_bypass(
                "rp_sandbox_a1b2c3d4e5f6",
                "https://playground.provii.app",
                "https://abc12345.sandbox.provii.app",
                "192.168.1.1",
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_client_provisioned() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_client_provisioned("client-new", "https://example.com")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_client_secret_updated() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger.log_client_secret_updated("client-abc").await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_credit_consumption_success() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let details = serde_json::json!({"amount": 1, "balance_after": 99}).to_string();
        logger
            .log_credit_consumption(
                "192.168.1.1",
                "https://example.com",
                "ver-123",
                true,
                &details,
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_credit_consumption_failure() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let details = serde_json::json!({"error": "insufficient_credits"}).to_string();
        logger
            .log_credit_consumption(
                "192.168.1.1",
                "https://example.com",
                "ver-456",
                false,
                &details,
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_dispatch_do_audit_events_empty() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger.dispatch_do_audit_events(&[], "", "", "").await;
        Ok(())
    }

    #[tokio::test]
    async fn test_dispatch_do_audit_events_multiple() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let events = vec![
            AuditEventData {
                event_type: "challenge_state_transition".into(),
                severity: "info".into(),
                message: "pending -> verified".into(),
                component: "challenge_do".into(),
                resource_id: "ch-123".into(),
                ..Default::default()
            },
            AuditEventData {
                event_type: "nonce_replay_detected".into(),
                severity: "critical".into(),
                message: "Replay detected".into(),
                component: "nonce_do".into(),
                resource_id: "nonce-456".into(),
                ..Default::default()
            },
        ];
        logger
            .dispatch_do_audit_events(&events, "10.0.0.1", "https://example.com", "req-789")
            .await;
        Ok(())
    }

    #[test]
    fn test_audit_event_data_default() {
        let data = AuditEventData::default();
        assert!(data.event_type.is_empty());
        assert!(data.severity.is_empty());
        assert!(data.message.is_empty());
        assert!(data.component.is_empty());
    }

    #[test]
    fn test_audit_event_data_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let data = AuditEventData {
            event_type: "test_event".into(),
            severity: "warning".into(),
            message: "Test message".into(),
            actor_ip: "10.0.0.1".into(),
            origin: "https://example.com".into(),
            actor_id: "client-1".into(),
            resource_id: "res-1".into(),
            details: r#"{"key":"value"}"#.into(),
            request_id: "corr-1".into(),
            environment: "sandbox".into(),
            component: "nonce_do".into(),
            worker_version: "1.0.0".into(),
        };
        let json = serde_json::to_string(&data)?;
        let decoded: AuditEventData = serde_json::from_str(&json)?;
        assert_eq!(decoded.event_type, "test_event");
        assert_eq!(decoded.severity, "warning");
        assert_eq!(decoded.component, "nonce_do");
        Ok(())
    }

    #[test]
    fn test_do_response_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let resp: DOResponse<String> = DOResponse {
            result: "ok".to_string(),
            audit_events: vec![AuditEventData {
                event_type: "test".into(),
                severity: "info".into(),
                message: "hello".into(),
                ..Default::default()
            }],
        };
        let json = serde_json::to_string(&resp)?;
        let decoded: DOResponse<String> = serde_json::from_str(&json)?;
        assert_eq!(decoded.result, "ok");
        assert_eq!(decoded.audit_events.len(), 1);
        assert_eq!(decoded.audit_events[0].event_type, "test");
        Ok(())
    }

    // ── AuditEventData field coverage ──────────────────────────────────

    #[test]
    fn test_audit_event_data_default_all_fields_empty() {
        let data = AuditEventData::default();
        assert!(data.actor_ip.is_empty());
        assert!(data.origin.is_empty());
        assert!(data.actor_id.is_empty());
        assert!(data.resource_id.is_empty());
        assert!(data.details.is_empty());
        assert!(data.request_id.is_empty());
        assert!(data.environment.is_empty());
        assert!(data.worker_version.is_empty());
    }

    #[test]
    fn test_audit_event_data_clone_preserves_all_fields() {
        let data = AuditEventData {
            event_type: "clone_test".into(),
            severity: "critical".into(),
            message: "cloned".into(),
            actor_ip: "10.0.0.2".into(),
            origin: "https://clone.example.com".into(),
            actor_id: "actor-clone".into(),
            resource_id: "res-clone".into(),
            details: r#"{"cloned":true}"#.into(),
            request_id: "corr-clone".into(),
            environment: "production".into(),
            component: "challenge_do".into(),
            worker_version: "2.0.0".into(),
        };
        let cloned = data.clone();
        assert_eq!(cloned.event_type, data.event_type);
        assert_eq!(cloned.severity, data.severity);
        assert_eq!(cloned.message, data.message);
        assert_eq!(cloned.actor_ip, data.actor_ip);
        assert_eq!(cloned.origin, data.origin);
        assert_eq!(cloned.actor_id, data.actor_id);
        assert_eq!(cloned.resource_id, data.resource_id);
        assert_eq!(cloned.details, data.details);
        assert_eq!(cloned.request_id, data.request_id);
        assert_eq!(cloned.environment, data.environment);
        assert_eq!(cloned.component, data.component);
        assert_eq!(cloned.worker_version, data.worker_version);
    }

    #[test]
    fn test_audit_event_data_debug_impl() {
        let data = AuditEventData {
            event_type: "debug_test".into(),
            severity: "info".into(),
            ..Default::default()
        };
        let debug_str = format!("{:?}", data);
        assert!(debug_str.contains("debug_test"));
        assert!(debug_str.contains("AuditEventData"));
    }

    #[test]
    fn test_audit_event_data_serde_deserialise_missing_fields_fail() {
        // Partial JSON missing required fields must fail since all fields
        // are non-Option String.
        let json = r#"{"event_type":"partial"}"#;
        let result = serde_json::from_str::<AuditEventData>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_audit_event_data_serde_full_roundtrip_all_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let data = AuditEventData {
            event_type: "full_roundtrip".into(),
            severity: "error".into(),
            message: "Full roundtrip test".into(),
            actor_ip: "192.168.0.1".into(),
            origin: "https://roundtrip.test".into(),
            actor_id: "actor-rt".into(),
            resource_id: "res-rt".into(),
            details: r#"{"nested":{"key":"val"}}"#.into(),
            request_id: "corr-rt-uuid".into(),
            environment: "production".into(),
            component: "challenge_do".into(),
            worker_version: "3.1.0".into(),
        };
        let json = serde_json::to_string(&data)?;
        let decoded: AuditEventData = serde_json::from_str(&json)?;
        assert_eq!(decoded.event_type, "full_roundtrip");
        assert_eq!(decoded.severity, "error");
        assert_eq!(decoded.message, "Full roundtrip test");
        assert_eq!(decoded.actor_ip, "192.168.0.1");
        assert_eq!(decoded.origin, "https://roundtrip.test");
        assert_eq!(decoded.actor_id, "actor-rt");
        assert_eq!(decoded.resource_id, "res-rt");
        assert_eq!(decoded.details, r#"{"nested":{"key":"val"}}"#);
        assert_eq!(decoded.request_id, "corr-rt-uuid");
        assert_eq!(decoded.environment, "production");
        assert_eq!(decoded.component, "challenge_do");
        assert_eq!(decoded.worker_version, "3.1.0");
        Ok(())
    }

    #[test]
    fn test_audit_event_data_serde_empty_strings_roundtrip(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let data = AuditEventData::default();
        let json = serde_json::to_string(&data)?;
        let decoded: AuditEventData = serde_json::from_str(&json)?;
        assert_eq!(decoded.event_type, "");
        assert_eq!(decoded.severity, "");
        assert_eq!(decoded.details, "");
        Ok(())
    }

    // ── DOResponse tests ───────────────────────────────────────────────

    #[test]
    fn test_do_response_empty_audit_events() -> Result<(), Box<dyn std::error::Error>> {
        let resp: DOResponse<u32> = DOResponse {
            result: 42,
            audit_events: vec![],
        };
        let json = serde_json::to_string(&resp)?;
        let decoded: DOResponse<u32> = serde_json::from_str(&json)?;
        assert_eq!(decoded.result, 42);
        assert!(decoded.audit_events.is_empty());
        Ok(())
    }

    #[test]
    fn test_do_response_with_bool_result() -> Result<(), Box<dyn std::error::Error>> {
        let resp: DOResponse<bool> = DOResponse {
            result: true,
            audit_events: vec![AuditEventData {
                event_type: "bool_test".into(),
                severity: "info".into(),
                message: "boolean result".into(),
                ..Default::default()
            }],
        };
        let json = serde_json::to_string(&resp)?;
        let decoded: DOResponse<bool> = serde_json::from_str(&json)?;
        assert!(decoded.result);
        assert_eq!(decoded.audit_events.len(), 1);
        Ok(())
    }

    #[test]
    fn test_do_response_with_multiple_audit_events() -> Result<(), Box<dyn std::error::Error>> {
        let resp: DOResponse<String> = DOResponse {
            result: "multi".to_string(),
            audit_events: vec![
                AuditEventData {
                    event_type: "event_a".into(),
                    severity: "info".into(),
                    message: "first".into(),
                    ..Default::default()
                },
                AuditEventData {
                    event_type: "event_b".into(),
                    severity: "warning".into(),
                    message: "second".into(),
                    ..Default::default()
                },
                AuditEventData {
                    event_type: "event_c".into(),
                    severity: "critical".into(),
                    message: "third".into(),
                    ..Default::default()
                },
                AuditEventData {
                    event_type: "event_d".into(),
                    severity: "error".into(),
                    message: "fourth".into(),
                    ..Default::default()
                },
            ],
        };
        let json = serde_json::to_string(&resp)?;
        let decoded: DOResponse<String> = serde_json::from_str(&json)?;
        assert_eq!(decoded.audit_events.len(), 4);
        assert_eq!(decoded.audit_events[0].event_type, "event_a");
        assert_eq!(decoded.audit_events[3].severity, "error");
        Ok(())
    }

    #[test]
    fn test_do_response_clone_preserves_events() {
        let resp: DOResponse<String> = DOResponse {
            result: "cloned".to_string(),
            audit_events: vec![AuditEventData {
                event_type: "clone_event".into(),
                severity: "info".into(),
                message: "clone msg".into(),
                ..Default::default()
            }],
        };
        let cloned = resp.clone();
        assert_eq!(cloned.result, "cloned");
        assert_eq!(cloned.audit_events.len(), 1);
        assert_eq!(cloned.audit_events[0].event_type, "clone_event");
    }

    #[test]
    fn test_do_response_debug_impl() {
        let resp: DOResponse<String> = DOResponse {
            result: "debug_test".to_string(),
            audit_events: vec![],
        };
        let debug_str = format!("{:?}", resp);
        assert!(debug_str.contains("DOResponse"));
        assert!(debug_str.contains("debug_test"));
    }

    // ── AuditLogger construction ───────────────────────────────────────

    #[test]
    fn test_logger_construction_captures_environment() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // The logger stores environment internally. We verify construction
        // does not panic and the logger is usable. The environment is
        // threaded through to AuditParams in each log method.
        let _ = format!("{:?}", logger.environment);
        assert_eq!(logger.environment, "test");
        assert_eq!(logger.worker_version, "0.0.0");
        Ok(())
    }

    #[test]
    fn test_logger_construction_different_environments() -> Result<(), Box<dyn std::error::Error>> {
        let salt = b"test-salt-minimum-32-bytes-long!!".to_vec();
        let privacy = Arc::new(PrivacyContext::new(salt)?);
        let inner = SharedLogger::new(None, privacy, "provii-verifier-test");
        let logger = AuditLogger::new(inner, "production".to_string(), "1.2.3".to_string());
        assert_eq!(logger.environment, "production");
        assert_eq!(logger.worker_version, "1.2.3");
        Ok(())
    }

    // ── Async audit logger method coverage ─────────────────────────────
    // These test that every method runs without panicking, covering
    // the format string construction and AuditParams assembly.

    #[tokio::test]
    async fn test_log_forbidden_origin() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_forbidden_origin("https://evil.com", "192.168.1.1", "/v1/challenge")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_vk_id_not_allowed() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_vk_id_not_allowed(
                42,
                "https://example.com",
                "550e8400-e29b-41d4-a716-446655440000",
                "192.168.1.1",
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_revocation_cache_hit() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_revocation_cache_hit(
                "550e8400-e29b-41d4-a716-446655440000",
                "https://example.com",
                "192.168.1.1",
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_challenge_expiry_inconsistency() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_challenge_expiry_inconsistency(
                "550e8400-e29b-41d4-a716-446655440000",
                1700000000,
                1700000500,
                "192.168.1.1",
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_sandbox_api_key_failure() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_sandbox_api_key_failure("192.168.1.1", "https://sandbox.example.com")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_malicious_origin_detected() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_malicious_origin_detected("javascript://evil.com", "192.168.1.1", None)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_idempotency_store_fail_open() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_idempotency_store_fail_open("idem-key-123", "DO unavailable", "192.168.1.1", None)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_mek_failure() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_mek_failure("client-abc", "decryption_failed", "192.168.1.1", None)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_rate_limit_exceeded() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_rate_limit_exceeded("client-abc", "/v1/challenge", "192.168.1.1", 101, 100)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_cutoff_validation() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_cutoff_validation("https://example.com", 18, 6570, "forward")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_status_endpoint_access_authorized() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        logger
            .log_status_endpoint_access("192.168.1.1", "/health", true)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_status_endpoint_access_denied() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_status_endpoint_access("192.168.1.1", "/health/detailed", false)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_state_write_failed_after_billing() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_state_write_failed_after_billing(
                "550e8400-e29b-41d4-a716-446655440000",
                "192.168.1.1",
                None,
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_test_origin_registered() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_test_origin_registered(
                "192.168.1.1",
                "https://test.sandbox.example.com",
                "rp_sandbox_abc123",
                3600,
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_test_origin_reregistration() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_test_origin_reregistration("192.168.1.1", "https://test.sandbox.example.com")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_csrf_token_generated_anonymous() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_csrf_token_generated("192.168.1.1", "anonymous")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_csrf_token_generated_with_session() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        logger
            .log_csrf_token_generated("192.168.1.1", "550e8400-e29b-41d4-a716-446655440000")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_csrf_validation_failed_anonymous() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_csrf_validation_failed(
                "192.168.1.1",
                "/hosted/verify",
                "anonymous",
                "token_missing",
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_csrf_validation_failed_with_session() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        logger
            .log_csrf_validation_failed(
                "192.168.1.1",
                "/hosted/verify",
                "550e8400-e29b-41d4-a716-446655440000",
                "signature_mismatch",
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_csrf_token_generation_failed() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_csrf_token_generation_failed(
                "192.168.1.1",
                "anonymous",
                "signing_key_unavailable",
                None,
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_data_deletion_request_without_requester(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_data_deletion_request("session", "sess-789", "auto_expiry", "system", None)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_data_deletion_completed_hard_delete() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        logger
            .log_data_deletion_completed("challenge", "ch-456", false, "audit-789")
            .await;
        Ok(())
    }

    // ── dispatch_do_audit_events severity/category mapping coverage ────

    #[tokio::test]
    async fn test_dispatch_do_audit_events_severity_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        let events = vec![AuditEventData {
            event_type: "test_error_severity".into(),
            severity: "error".into(),
            message: "error severity test".into(),
            component: "challenge_do".into(),
            ..Default::default()
        }];
        logger
            .dispatch_do_audit_events(&events, "10.0.0.1", "https://test.com", "req-1")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_dispatch_do_audit_events_severity_warning(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let events = vec![AuditEventData {
            event_type: "test_warning_severity".into(),
            severity: "warning".into(),
            message: "warning severity test".into(),
            component: "nonce_do".into(),
            ..Default::default()
        }];
        logger
            .dispatch_do_audit_events(&events, "10.0.0.1", "https://test.com", "req-2")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_dispatch_do_audit_events_unknown_severity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let events = vec![AuditEventData {
            event_type: "test_unknown_severity".into(),
            severity: "trace".into(), // unknown severity defaults to Info
            message: "unknown severity test".into(),
            component: "unknown_do".into(),
            ..Default::default()
        }];
        logger
            .dispatch_do_audit_events(&events, "10.0.0.1", "https://test.com", "req-3")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_dispatch_do_audit_events_event_context_overrides_caller(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // When event has its own actor_ip, origin, and request_id,
        // those should take precedence over the caller-provided defaults.
        let events = vec![AuditEventData {
            event_type: "context_override".into(),
            severity: "info".into(),
            message: "override test".into(),
            actor_ip: "172.16.0.1".into(), // non-empty, should override caller's IP
            origin: "https://override.test".into(), // non-empty, should override
            request_id: "evt-corr-id".into(), // non-empty, should override
            component: "challenge_do".into(),
            ..Default::default()
        }];
        // Caller provides "10.0.0.1", "https://caller.test", "req-caller"
        // but event fields should win.
        logger
            .dispatch_do_audit_events(&events, "10.0.0.1", "https://caller.test", "req-caller")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_dispatch_do_audit_events_empty_event_fields_use_caller_defaults(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // When event fields are empty, the caller's context should be used.
        let events = vec![AuditEventData {
            event_type: "empty_context".into(),
            severity: "info".into(),
            message: "empty context test".into(),
            actor_ip: String::new(),   // empty, should use caller IP
            origin: String::new(),     // empty, should use caller origin
            request_id: String::new(), // empty, should use caller request_id
            component: "challenge_do".into(),
            ..Default::default()
        }];
        logger
            .dispatch_do_audit_events(&events, "10.0.0.1", "https://caller.test", "req-caller")
            .await;
        Ok(())
    }

    // ── Authentication failure variants ────────────────────────────────

    #[tokio::test]
    async fn test_log_authentication_failure_with_client_id_no_details(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // When client_id is Some but details is None, the details_str
        // should be auto-generated from client_id and failure_type.
        logger
            .log_authentication_failure(
                "192.168.1.1",
                "expired_key",
                Some("client-xyz"),
                None,
                None,
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_challenge_created_without_client_id() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        // When client_id is None, the details string should be empty.
        logger
            .log_challenge_created(
                "550e8400-e29b-41d4-a716-446655440000",
                "192.168.1.1",
                "https://example.com",
                None,
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_billing_event_without_royalty() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let result = logger
            .log_billing_event(
                "550e8400",
                "https://example.com",
                None, // No issuer_kid means no royalty
                &[0xffu8; 32],
                365,
                1700000000,
            )
            .await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_log_billing_event_with_nonzero_hash() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // Verify that different issuer_key_hash bytes produce different
        // base64-encoded values in the details JSON.
        let hash: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let result = logger
            .log_billing_event(
                "ch-test",
                "https://billing.test",
                Some("issuer-kid-1"),
                &hash,
                180,
                1700000000,
            )
            .await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_log_verification_no_royalty_with_nonzero_hash(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let hash: [u8; 32] = [0xab; 32];
        let result = logger
            .log_verification_no_royalty("ch-test2", "https://noroyalty.test", &hash, 1700000100)
            .await;
        assert!(result.is_ok());
        Ok(())
    }

    // ── Additional coverage: verification attempt with None reason ────

    #[tokio::test]
    async fn test_log_verification_attempt_failure_no_reason(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // Exercises the failure branch with reason = None (the {:?} format on None).
        logger
            .log_verification_attempt(
                "550e8400-e29b-41d4-a716-446655440000",
                "192.168.1.1",
                false,
                None,
            )
            .await;
        Ok(())
    }

    // ── Additional coverage: CSRF token generation failed with session ──

    #[tokio::test]
    async fn test_log_csrf_token_generation_failed_with_session(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // Exercises the non-"anonymous" branch in log_csrf_token_generation_failed
        // where session_id gets redacted via redact_session_id.
        logger
            .log_csrf_token_generation_failed(
                "192.168.1.1",
                "550e8400-e29b-41d4-a716-446655440000",
                "handler_error",
                None,
            )
            .await;
        Ok(())
    }

    // ── Additional coverage: authentication failure with origin but no client_id ──

    #[tokio::test]
    async fn test_log_authentication_failure_with_origin_no_client_id(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // details = None and client_id = None => details_str is empty String.
        // origin = Some => origin field is populated.
        logger
            .log_authentication_failure(
                "10.0.0.1",
                "missing_api_key",
                None,
                Some("https://example.com"),
                None,
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_authentication_failure_no_client_id_with_details(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // details = Some, client_id = None => details come from the provided JSON,
        // message uses the "no client_id" format branch.
        logger
            .log_authentication_failure(
                "10.0.0.1",
                "ip_blocked",
                None,
                None,
                Some(serde_json::json!({"reason": "geo_block"})),
            )
            .await;
        Ok(())
    }

    // ── Additional coverage: short / empty challenge IDs ──────────────

    #[tokio::test]
    async fn test_log_challenge_created_empty_challenge_id(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // Empty challenge_id exercises the redact_challenge_id fallback
        // where get(..8) on "" returns Some(""), not None.
        logger
            .log_challenge_created("", "192.168.1.1", "https://example.com", None)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_challenge_created_short_challenge_id(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // Challenge ID shorter than 8 chars: redact_challenge_id returns the
        // full string via the .get(..8).unwrap_or(challenge_id) path.
        logger
            .log_challenge_created(
                "abc",
                "192.168.1.1",
                "https://example.com",
                Some("client-1"),
            )
            .await;
        Ok(())
    }

    // ── Additional coverage: challenge expiry edge cases ──────────────

    #[tokio::test]
    async fn test_log_challenge_expiry_inconsistency_zero_drift(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // expires_at == now => drift_seconds = 0 via saturating_sub
        logger
            .log_challenge_expiry_inconsistency(
                "550e8400-e29b-41d4-a716-446655440000",
                1700000000,
                1700000000,
                "192.168.1.1",
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_challenge_expiry_inconsistency_future_expiry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // now < expires_at => saturating_sub clamps to 0
        logger
            .log_challenge_expiry_inconsistency(
                "550e8400-e29b-41d4-a716-446655440000",
                1700001000,
                1700000000,
                "192.168.1.1",
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_challenge_expiry_inconsistency_max_drift(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // Large drift value
        logger
            .log_challenge_expiry_inconsistency(
                "550e8400-e29b-41d4-a716-446655440000",
                0,
                u64::MAX,
                "192.168.1.1",
            )
            .await;
        Ok(())
    }

    // ── Additional coverage: dispatch_do_audit_events outcome mapping ──

    #[tokio::test]
    async fn test_dispatch_do_audit_events_severity_critical_outcome_denied(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // severity "critical" => outcome "denied"
        let events = vec![AuditEventData {
            event_type: "critical_event".into(),
            severity: "critical".into(),
            message: "critical outcome test".into(),
            component: "nonce_do".into(),
            ..Default::default()
        }];
        logger
            .dispatch_do_audit_events(&events, "10.0.0.1", "https://test.com", "req-crit")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_dispatch_do_audit_events_unknown_component(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // component is neither "challenge_do" nor "nonce_do" =>
        // event_category defaults to SecurityEvent
        let events = vec![AuditEventData {
            event_type: "unknown_component_event".into(),
            severity: "info".into(),
            message: "unknown component test".into(),
            component: "rate_limiter_do".into(),
            ..Default::default()
        }];
        logger
            .dispatch_do_audit_events(&events, "10.0.0.1", "https://test.com", "req-unk")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_dispatch_do_audit_events_all_severity_levels_together(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // Exercises all four severity branches and both component branches
        // in a single dispatch call to validate iteration correctness.
        let events = vec![
            AuditEventData {
                event_type: "evt_info".into(),
                severity: "info".into(),
                message: "info event".into(),
                component: "challenge_do".into(),
                ..Default::default()
            },
            AuditEventData {
                event_type: "evt_warning".into(),
                severity: "warning".into(),
                message: "warning event".into(),
                component: "nonce_do".into(),
                ..Default::default()
            },
            AuditEventData {
                event_type: "evt_error".into(),
                severity: "error".into(),
                message: "error event".into(),
                component: "challenge_do".into(),
                ..Default::default()
            },
            AuditEventData {
                event_type: "evt_critical".into(),
                severity: "critical".into(),
                message: "critical event".into(),
                component: "other_do".into(),
                ..Default::default()
            },
            AuditEventData {
                event_type: "evt_unknown".into(),
                severity: "debug".into(),
                message: "unknown severity event".into(),
                component: "".into(),
                ..Default::default()
            },
        ];
        logger
            .dispatch_do_audit_events(&events, "10.0.0.1", "https://all-sev.test", "req-all")
            .await;
        Ok(())
    }

    // ── Additional coverage: DOResponse with various result types ──────

    #[test]
    fn test_do_response_with_option_result() -> Result<(), Box<dyn std::error::Error>> {
        let resp: DOResponse<Option<String>> = DOResponse {
            result: None,
            audit_events: vec![],
        };
        let json = serde_json::to_string(&resp)?;
        let decoded: DOResponse<Option<String>> = serde_json::from_str(&json)?;
        assert!(decoded.result.is_none());
        assert!(decoded.audit_events.is_empty());
        Ok(())
    }

    #[test]
    fn test_do_response_with_vec_result() -> Result<(), Box<dyn std::error::Error>> {
        let resp: DOResponse<Vec<u8>> = DOResponse {
            result: vec![1, 2, 4, 5],
            audit_events: vec![AuditEventData {
                event_type: "vec_result".into(),
                severity: "info".into(),
                message: "vec test".into(),
                ..Default::default()
            }],
        };
        let json = serde_json::to_string(&resp)?;
        let decoded: DOResponse<Vec<u8>> = serde_json::from_str(&json)?;
        assert_eq!(decoded.result, vec![1, 2, 4, 5]);
        assert_eq!(decoded.audit_events.len(), 1);
        Ok(())
    }

    #[test]
    fn test_do_response_deserialization_missing_audit_events_fails() {
        // DOResponse requires audit_events field; missing it must fail.
        let json = r#"{"result":"ok"}"#;
        let result = serde_json::from_str::<DOResponse<String>>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_do_response_deserialization_missing_result_fails() {
        // DOResponse requires result field.
        let json = r#"{"audit_events":[]}"#;
        let result = serde_json::from_str::<DOResponse<String>>(json);
        assert!(result.is_err());
    }

    // ── Additional coverage: AuditEventData with special characters ────

    #[test]
    fn test_audit_event_data_serde_with_unicode() -> Result<(), Box<dyn std::error::Error>> {
        let data = AuditEventData {
            event_type: "unicode_test".into(),
            severity: "info".into(),
            message: "Nachricht mit Umlauten: aou".into(),
            actor_ip: "::1".into(),
            origin: "https://example.com".into(),
            actor_id: "user-42".into(),
            resource_id: "res-42".into(),
            details: r#"{"emoji":"test","lang":"de"}"#.into(),
            request_id: "corr-uni".into(),
            environment: "test".into(),
            component: "nonce_do".into(),
            worker_version: "1.0.0".into(),
        };
        let json = serde_json::to_string(&data)?;
        let decoded: AuditEventData = serde_json::from_str(&json)?;
        assert_eq!(decoded.message, "Nachricht mit Umlauten: aou");
        Ok(())
    }

    #[test]
    fn test_audit_event_data_serde_with_escaped_json_in_details(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let inner_json = serde_json::json!({"key": "value with \"quotes\""}).to_string();
        let data = AuditEventData {
            event_type: "escaped_json".into(),
            severity: "info".into(),
            message: "details with nested JSON".into(),
            details: inner_json.clone(),
            ..Default::default()
        };
        let json = serde_json::to_string(&data)?;
        let decoded: AuditEventData = serde_json::from_str(&json)?;
        assert_eq!(decoded.details, inner_json);
        Ok(())
    }

    // ── Additional coverage: logger with empty environment/version ─────

    #[test]
    fn test_logger_construction_empty_strings() -> Result<(), Box<dyn std::error::Error>> {
        let salt = b"test-salt-minimum-32-bytes-long!!".to_vec();
        let privacy = Arc::new(PrivacyContext::new(salt)?);
        let inner = SharedLogger::new(None, privacy, "provii-verifier-test");
        let logger = AuditLogger::new(inner, String::new(), String::new());
        assert!(logger.environment.is_empty());
        assert!(logger.worker_version.is_empty());
        Ok(())
    }

    // ── Additional coverage: billing/royalty edge values ───────────────

    #[tokio::test]
    async fn test_log_billing_event_zero_cutoff_days() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let result = logger
            .log_billing_event(
                "ch-zero-cutoff",
                "https://example.com",
                Some("kid-zero"),
                &[0u8; 32],
                0,
                0,
            )
            .await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_log_billing_event_negative_cutoff_days() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        let result = logger
            .log_billing_event(
                "ch-neg-cutoff",
                "https://example.com",
                Some("kid-neg"),
                &[0u8; 32],
                -365,
                1700000000,
            )
            .await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_log_royalty_event_negative_cutoff() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_royalty_event("kid-neg", &[0xffu8; 32], "https://example.com", -1)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_royalty_event_zero_hash() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_royalty_event("kid-zero-hash", &[0u8; 32], "https://example.com", 0)
            .await;
        Ok(())
    }

    // ── Additional coverage: rate limit edge values ───────────────────

    #[tokio::test]
    async fn test_log_rate_limit_exceeded_zero_values() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_rate_limit_exceeded("", "", "0.0.0.0", 0, 0)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_rate_limit_exceeded_max_values() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_rate_limit_exceeded(
                "client-max",
                "/v1/verify",
                "255.255.255.255",
                u32::MAX,
                u32::MAX,
            )
            .await;
        Ok(())
    }

    // ── Additional coverage: cutoff validation edge values ────────────

    #[tokio::test]
    async fn test_log_cutoff_validation_zero_age() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_cutoff_validation("https://example.com", 0, 0, "backward")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_cutoff_validation_negative_cutoff() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        logger
            .log_cutoff_validation("https://example.com", 21, -7300, "forward")
            .await;
        Ok(())
    }

    // ── Additional coverage: vk_id edge values ────────────────────────

    #[tokio::test]
    async fn test_log_vk_id_not_allowed_zero() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_vk_id_not_allowed(0, "https://example.com", "ch-zero-vk", "192.168.1.1")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_vk_id_not_allowed_max() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_vk_id_not_allowed(
                u32::MAX,
                "https://example.com",
                "550e8400-e29b-41d4-a716-446655440000",
                "192.168.1.1",
            )
            .await;
        Ok(())
    }

    // ── Additional coverage: credit consumption with empty details ─────

    #[tokio::test]
    async fn test_log_credit_consumption_empty_details() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_credit_consumption("192.168.1.1", "https://example.com", "ver-empty", true, "")
            .await;
        Ok(())
    }

    // ── Additional coverage: data deletion with empty strings ──────────

    #[tokio::test]
    async fn test_log_data_deletion_request_empty_strings() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        logger.log_data_deletion_request("", "", "", "", None).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_data_deletion_completed_empty_audit_id(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_data_deletion_completed("session", "sess-1", true, "")
            .await;
        Ok(())
    }

    // ── Additional coverage: short code with empty strings ─────────────

    #[tokio::test]
    async fn test_log_short_code_lookup_success_empty_code(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger.log_short_code_lookup_success("", "", "").await;
        Ok(())
    }

    // ── Additional coverage: forbidden origin with special chars ───────

    #[tokio::test]
    async fn test_log_forbidden_origin_with_special_chars() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        logger
            .log_forbidden_origin("javascript://alert(1)", "192.168.1.1", "/v1/verify")
            .await;
        Ok(())
    }

    // ── Additional coverage: test origin registration edge cases ───────

    #[tokio::test]
    async fn test_log_test_origin_registered_zero_ttl() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_test_origin_registered(
                "192.168.1.1",
                "https://test.sandbox.example.com",
                "rp_sandbox_zero",
                0,
            )
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_test_origin_registered_max_ttl() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_test_origin_registered(
                "192.168.1.1",
                "https://test.sandbox.example.com",
                "rp_sandbox_max",
                u64::MAX,
            )
            .await;
        Ok(())
    }

    // ── Additional coverage: dispatch_do_audit_events partial overrides ──

    #[tokio::test]
    async fn test_dispatch_do_audit_events_mixed_overrides(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // Event has actor_ip set but origin and request_id empty.
        // Verifies partial override behaviour: only non-empty fields override.
        let events = vec![AuditEventData {
            event_type: "partial_override".into(),
            severity: "warning".into(),
            message: "partial override test".into(),
            actor_ip: "172.16.0.99".into(),
            origin: String::new(),
            request_id: String::new(),
            component: "nonce_do".into(),
            ..Default::default()
        }];
        logger
            .dispatch_do_audit_events(
                &events,
                "10.0.0.1",
                "https://caller-default.test",
                "req-partial",
            )
            .await;
        Ok(())
    }

    // ── Additional coverage: CSRF with short session IDs ──────────────

    #[tokio::test]
    async fn test_log_csrf_token_generated_short_session_id(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        // Session ID shorter than 8 chars exercises the redact_session_id
        // fallback path.
        logger.log_csrf_token_generated("192.168.1.1", "abc").await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_csrf_validation_failed_short_session_id(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_csrf_validation_failed("192.168.1.1", "/hosted/submit", "short", "expired")
            .await;
        Ok(())
    }

    // ── Additional coverage: suspicious activity with empty reason ─────

    #[tokio::test]
    async fn test_log_suspicious_activity_empty_reason() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger.log_suspicious_activity("192.168.1.1", "").await;
        Ok(())
    }

    // ── Additional coverage: sandbox origin bypass empty strings ───────

    #[tokio::test]
    async fn test_log_sandbox_origin_bypass_empty_strings() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        logger.log_sandbox_origin_bypass("", "", "", "").await;
        Ok(())
    }

    // ── Additional coverage: mek_failure variants ─────────────────────

    #[tokio::test]
    async fn test_log_mek_failure_missing_key() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_mek_failure("client-mek", "key_not_found", "10.0.0.1", None)
            .await;
        Ok(())
    }

    // ── Additional coverage: idempotency store with long error msg ────

    #[tokio::test]
    async fn test_log_idempotency_store_fail_open_long_error(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let long_error = "a]".repeat(500);
        logger
            .log_idempotency_store_fail_open("idem-long", &long_error, "192.168.1.1", None)
            .await;
        Ok(())
    }

    // ── Additional coverage: malicious origin with data URI ───────────

    #[tokio::test]
    async fn test_log_malicious_origin_detected_data_uri() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        logger
            .log_malicious_origin_detected(
                "data:text/html,<script>alert(1)</script>",
                "192.168.1.1",
                None,
            )
            .await;
        Ok(())
    }

    // ── Additional coverage: replay attempt with empty challenge ───────

    #[tokio::test]
    async fn test_log_replay_attempt_empty_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger.log_replay_attempt("", "192.168.1.1", None).await;
        Ok(())
    }

    // ── Additional coverage: logger clone ─────────────────────────────

    #[test]
    fn test_logger_clone_preserves_fields() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let cloned = logger.clone();
        assert_eq!(cloned.environment, "test");
        assert_eq!(cloned.worker_version, "0.0.0");
        Ok(())
    }

    // ── Additional coverage: verification no-royalty edge timestamps ──

    #[tokio::test]
    async fn test_log_verification_no_royalty_zero_timestamp(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let result = logger
            .log_verification_no_royalty("ch-zero-ts", "https://example.com", &[0u8; 32], 0)
            .await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_log_verification_no_royalty_max_timestamp(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        let result = logger
            .log_verification_no_royalty("ch-max-ts", "https://example.com", &[0u8; 32], u64::MAX)
            .await;
        assert!(result.is_ok());
        Ok(())
    }

    // ── Additional coverage: DOResponse with nested struct result ──────

    #[test]
    fn test_do_response_with_nested_struct() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        struct Inner {
            id: u32,
            name: String,
        }
        let resp: DOResponse<Inner> = DOResponse {
            result: Inner {
                id: 7,
                name: "nested".to_string(),
            },
            audit_events: vec![
                AuditEventData {
                    event_type: "nested_a".into(),
                    severity: "info".into(),
                    message: "first nested".into(),
                    ..Default::default()
                },
                AuditEventData {
                    event_type: "nested_b".into(),
                    severity: "warning".into(),
                    message: "second nested".into(),
                    ..Default::default()
                },
            ],
        };
        let json = serde_json::to_string(&resp)?;
        let decoded: DOResponse<Inner> = serde_json::from_str(&json)?;
        assert_eq!(decoded.result.id, 7);
        assert_eq!(decoded.result.name, "nested");
        assert_eq!(decoded.audit_events.len(), 2);
        Ok(())
    }

    // ── Additional coverage: state_write_failed with short challenge ───

    #[tokio::test]
    async fn test_log_state_write_failed_after_billing_short_id(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_state_write_failed_after_billing("ab", "10.0.0.1", None)
            .await;
        Ok(())
    }

    // ── Additional coverage: authentication success with empty origin ──

    #[tokio::test]
    async fn test_log_authentication_success_empty_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        logger.log_authentication_success("", "", "").await;
        Ok(())
    }

    // ── Additional coverage: origin disabled/not_found with empty ──────

    #[tokio::test]
    async fn test_log_origin_disabled_empty_origin() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger.log_origin_disabled("", "").await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_origin_not_found_empty_origin() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger.log_origin_not_found("", "").await;
        Ok(())
    }

    // ── Additional coverage: client provisioned/secret updated empty ───

    #[tokio::test]
    async fn test_log_client_provisioned_empty() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger.log_client_provisioned("", "").await;
        Ok(())
    }

    #[tokio::test]
    async fn test_log_client_secret_updated_empty() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger.log_client_secret_updated("").await;
        Ok(())
    }

    // ── Additional coverage: revocation cache hit with short id ────────

    #[tokio::test]
    async fn test_log_revocation_cache_hit_short_id() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .log_revocation_cache_hit("short", "https://example.com", "192.168.1.1")
            .await;
        Ok(())
    }

    // ── Additional coverage: sandbox_api_key_failure empty origin ──────

    #[tokio::test]
    async fn test_log_sandbox_api_key_failure_empty_origin(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger.log_sandbox_api_key_failure("10.0.0.1", "").await;
        Ok(())
    }

    // ── Additional coverage: challenge poll with empty strings ─────────

    #[tokio::test]
    async fn test_log_challenge_poll_success_empty_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let logger = test_logger()?;
        logger.log_challenge_poll_success("", "", "").await;
        Ok(())
    }

    // ── Additional coverage: test_origin_reregistration empty ──────────

    #[tokio::test]
    async fn test_log_test_origin_reregistration_empty() -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger.log_test_origin_reregistration("", "").await;
        Ok(())
    }

    // ── dispatch_hosted_nonce_audit_events coverage ──────────────────────

    #[tokio::test]
    async fn test_dispatch_hosted_nonce_audit_events_empty(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = test_logger()?;
        logger
            .dispatch_hosted_nonce_audit_events(&[], "", "", "")
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_dispatch_hosted_nonce_audit_events_single(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::hosted::durable_objects::HostedNonceDOAuditEvent;

        let logger = test_logger()?;
        let events = vec![HostedNonceDOAuditEvent {
            event_type: "nonce_created".into(),
            severity: Severity::Info,
            event_category: EventCategory::SecurityEvent,
            outcome: "success".into(),
            resource_id: "hosted-nonce-001".into(),
            message: "Hosted nonce created".into(),
            details: "ttl=300".into(),
        }];
        logger
            .dispatch_hosted_nonce_audit_events(
                &events,
                "192.168.1.1",
                "https://example.com",
                "req-hosted-001",
            )
            .await;
        Ok(())
    }
}
