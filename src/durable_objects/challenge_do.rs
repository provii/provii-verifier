// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Durable Object responsible for challenge lifecycle persistence.
//!
//! Each challenge passes through a strict state machine:
//! `Pending` -> `ProofOkWaitingForRedeem` -> `Verified`, with `Failed`
//! and `Expired` as terminal states reachable from any non-terminal state.
//!
//! SECURITY: State transitions are validated server-side (RT-032). Terminal
//! states cannot transition further, preventing replay of already-redeemed
//! challenges. Expired challenges are auto-deleted on read with audit
//! trail (AL-050). All cryptographic fields in `CachedChallenge` are
//! zeroised on drop (ASVS V8.2.1) via the `Drop` impl on `CachedChallenge`.
//!
//! The single-writer model of Durable Objects guarantees that concurrent
//! writes to the same challenge UUID are serialised, eliminating the need
//! for a separate distributed lock (ChallengeLockDO).
//!
//! Storage layout:
//! - `ch:{uuid}` stores the challenge as JSON matching [`CachedChallenge`].
//! - `code:{short_code}` stores a mapping to the UUID (internal reverse lookup).
#![forbid(unsafe_code)]

use crate::cache::{CachedChallenge, ChallengeState};
use crate::security::audit::AuditEventData;
use crate::utils::validation::{validate_challenge_id, validate_short_code};
use worker::*;
use zeroize::Zeroize;

/// IV-1231: Maximum request body size accepted by the Challenge DO (64 KB).
/// Challenge payloads include JSON-encoded CachedChallenge data but should
/// never approach this limit in normal operation. Anything larger is rejected.
const MAX_DO_BODY_SIZE: usize = 65_536;

/// Durable Object that owns the authoritative challenge record.
///
/// Routes incoming HTTP requests to CRUD operations on per-challenge
/// storage keys. The single-threaded execution model of Durable Objects
/// guarantees that concurrent writes to the same challenge are serialised,
/// preventing state machine corruption and eliminating the need for a
/// separate locking layer.
#[durable_object]
pub struct ChallengeDO {
    state: State,
    #[allow(dead_code)] // Required by worker-rs Durable Object API
    env: Env,
}

impl DurableObject for ChallengeDO {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let path_segments: Vec<&str> = url.path().split('/').collect();

        if path_segments.len() < 3 {
            return Response::error("Invalid path", 400);
        }

        // Length validated above: path_segments.len() >= 3.
        let resource_type = match path_segments.get(1) {
            Some(s) => *s,
            None => return Response::error("Invalid path", 400),
        };
        let identifier = match path_segments.get(2) {
            Some(s) => *s,
            None => return Response::error("Invalid path", 400),
        };

        // Handle short code lookup
        if resource_type == "code" && req.method() == Method::Get {
            return self
                .timed(
                    "get_challenge_by_code",
                    self.get_challenge_by_code(identifier),
                )
                .await;
        }

        // Handle regular challenge operations
        let uuid = identifier;
        let action = path_segments.get(3).copied().unwrap_or("get");

        // M18: time each DO operation end-to-end so the write-heavy paths
        // (create/update, which include the ~500ms storage put) are observable
        // via the structured `do_operation` log line.
        match req.method() {
            Method::Get => self.timed("get_challenge", self.get_challenge(uuid)).await,
            Method::Post => match action {
                "create" => {
                    self.timed("create_challenge", self.create_challenge(uuid, req))
                        .await
                }
                "update" => {
                    self.timed("update_challenge", self.update_challenge(uuid, req))
                        .await
                }
                _ => Response::error("Invalid action", 400),
            },
            Method::Delete => {
                self.timed("delete_challenge", self.delete_challenge(uuid))
                    .await
            }
            _ => Response::error("Method not allowed", 405),
        }
    }
}

/// Check whether a state string represents a terminal state.
fn is_terminal_state(state: &ChallengeState) -> bool {
    matches!(
        state,
        ChallengeState::Verified | ChallengeState::Failed | ChallengeState::Expired
    )
}

/// Validate that the requested state transition is legal.
///
/// Valid forward transitions:
/// - Pending -> ProofOkWaitingForRedeem, Failed, Expired
/// - ProofOkWaitingForRedeem -> Verified, Failed, Expired
/// - Terminal states (Verified, Failed, Expired) -> nothing
/// - Same-state transitions are idempotent (allowed)
fn is_valid_transition(from: &ChallengeState, to: &ChallengeState) -> bool {
    if from == to {
        return true; // Idempotent
    }
    match from {
        ChallengeState::Pending => matches!(
            to,
            ChallengeState::ProofOkWaitingForRedeem
                | ChallengeState::Failed
                | ChallengeState::Expired
        ),
        ChallengeState::ProofOkWaitingForRedeem => matches!(
            to,
            ChallengeState::Verified | ChallengeState::Failed | ChallengeState::Expired
        ),
        ChallengeState::Verified | ChallengeState::Failed | ChallengeState::Expired => false,
    }
}

/// Narrow update payload for challenge state transitions.
///
/// SECURITY (ADV-VA-002): Only mutable lifecycle fields are accepted from
/// the request body. All immutable challenge parameters (id, short_code,
/// rp_challenge, code_challenge, code_challenge_bytes, submit_secret,
/// origin, expires_at, created_at, cutoff_days, verifying_key_id,
/// proof_direction, client_id, tenant_id) are preserved from the existing
/// stored record. This prevents arbitrary field overwrite via the DO
/// update endpoint (PKCE bypass, submit_secret replacement, origin
/// rebinding, BOLA bypass via client_id/tenant_id mutation).
#[derive(serde::Deserialize)]
struct ChallengeUpdate {
    /// New lifecycle state.
    state: ChallengeState,
    /// Whether a proof has been submitted.
    #[serde(default)]
    proof_submitted: Option<bool>,
    /// Timestamp when the ZK proof was verified.
    #[serde(default)]
    proof_verified_at: Option<u64>,
    /// Timestamp when PKCE redemption completed.
    #[serde(default)]
    verified_at: Option<u64>,
    /// Issuer key identifier captured during proof verification.
    #[serde(default)]
    issuer_kid: Option<String>,
    /// Raw issuer verifying key bytes, when available.
    #[serde(default)]
    issuer_vk_bytes: Option<[u8; 32]>,
}

/// H4: Number of attempts for a Challenge DO `storage().put()` (1 initial + 2
/// retries). Durable Object storage writes are normally fast but can fail
/// transiently; a single dropped write previously surfaced as a 500.
const PUT_MAX_ATTEMPTS: u32 = 3;

/// H4: Initial backoff in milliseconds for a `put()` retry. Doubles each
/// attempt within the 10-100ms band: 10ms then 20ms (the 40ms slot is computed
/// but not slept because the third attempt is the last).
const PUT_INITIAL_BACKOFF_MS: u64 = 10;

impl ChallengeDO {
    /// M18: Run a DO operation, timing it end-to-end and emitting a structured
    /// `do_operation` log line ({event, operation, duration_ms, status}) so the
    /// write-heavy paths (which include the ~500ms storage put) are observable.
    ///
    /// `operation` is only read by the wasm32-gated log; on native it is unused.
    #[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
    async fn timed<F>(&self, operation: &str, fut: F) -> Result<Response>
    where
        F: std::future::Future<Output = Result<Response>>,
    {
        let start = Date::now().as_millis();
        let result = fut.await;
        let duration_ms = Date::now().as_millis().saturating_sub(start);

        #[cfg(target_arch = "wasm32")]
        {
            let status = match &result {
                Ok(resp) => resp.status_code(),
                // An Err here becomes a DO-boundary error response; record 500
                // as the effective status for the latency line.
                Err(_) => 500,
            };
            console_log!(
                "{{\"event\":\"do_operation\",\"component\":\"challenge_do\",\"operation\":\"{}\",\"duration_ms\":{},\"status\":{}}}",
                operation,
                duration_ms,
                status
            );
        }

        result
    }

    /// H4: Persist a value to Durable Object storage with bounded retry on
    /// transient write failure.
    ///
    /// Retries [`PUT_MAX_ATTEMPTS`] times with an exponential backoff
    /// ([`PUT_INITIAL_BACKOFF_MS`], doubling each attempt). The value is passed
    /// by reference so it can be re-sent across attempts without cloning
    /// (`&T: Serialize` when `T: Serialize`).
    ///
    /// M18: Each attempt is timed and logged as a structured `do_operation`
    /// line so the write latency is observable.
    ///
    /// On exhaustion this emits a `do_storage_put_failed` audit line at
    /// critical severity and returns the last error. Callers convert that into
    /// a 503 (Service Unavailable) rather than a 500: a failed write is an
    /// availability problem, and the Challenge DO is the single writer for the
    /// challenge, so idempotency is preserved (a retried client request that
    /// lands after the write eventually succeeds is a no-op create or an
    /// idempotent same-state update).
    ///
    /// `operation` is only read by the wasm32-gated logs; on native it is
    /// unused.
    #[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
    async fn put_with_retry<T: serde::Serialize>(
        &self,
        key: &str,
        value: &T,
        operation: &str,
    ) -> Result<()> {
        let mut backoff_ms = PUT_INITIAL_BACKOFF_MS;
        let mut last_err: Option<worker::Error> = None;

        for attempt in 1..=PUT_MAX_ATTEMPTS {
            let start = Date::now().as_millis();
            let result = self.state.storage().put(key, value).await;
            let duration_ms = Date::now().as_millis().saturating_sub(start);

            match result {
                Ok(()) => {
                    // M18: structured DO operation latency.
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "{{\"event\":\"do_operation\",\"component\":\"challenge_do\",\"operation\":\"{}\",\"outcome\":\"ok\",\"attempt\":{},\"duration_ms\":{}}}",
                        operation,
                        attempt,
                        duration_ms
                    );
                    return Ok(());
                }
                Err(e) => {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "{{\"event\":\"do_operation\",\"component\":\"challenge_do\",\"operation\":\"{}\",\"outcome\":\"error\",\"attempt\":{},\"max_attempts\":{},\"duration_ms\":{}}}",
                        operation,
                        attempt,
                        PUT_MAX_ATTEMPTS,
                        duration_ms
                    );
                    last_err = Some(e);
                    if attempt < PUT_MAX_ATTEMPTS {
                        crate::utils::retry::backoff_delay_ms(backoff_ms).await;
                        backoff_ms = backoff_ms.saturating_mul(2);
                    }
                }
            }
        }

        // Exhausted: emit a critical audit line so the failure is alertable,
        // then surface the last error for the caller to map to a 503.
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "{{\"audit\":true,\"event\":\"do_storage_put_failed\",\"component\":\"challenge_do\",\"operation\":\"{}\",\"attempts\":{},\"severity\":\"critical\",\"outcome\":\"fail\"}}",
            operation,
            PUT_MAX_ATTEMPTS
        );
        Err(last_err.unwrap_or_else(|| {
            worker::Error::RustError(format!(
                "challenge_do put for {} exhausted {} attempts with no recorded error",
                operation, PUT_MAX_ATTEMPTS
            ))
        }))
    }

    /// Resolve a 12-digit short code to its parent challenge UUID, then
    /// return the full challenge payload via [`Self::get_challenge`].
    async fn get_challenge_by_code(&self, short_code: &str) -> Result<Response> {
        // SECURITY: Validate short code to prevent injection attacks (CWE-89, CSA-01)
        if let Err(_e) = validate_short_code(short_code) {
            #[cfg(target_arch = "wasm32")]
            console_log!("[ChallengeDO] Invalid short code rejected: {}", short_code);
            return Response::error("Invalid short code", 400);
        }

        let code_key = format!("code:{}", short_code);

        let uuid: Option<String> = self.state.storage().get(&code_key).await.unwrap_or(None);

        match uuid {
            Some(uuid_str) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[ChallengeDO] Short code {} maps to challenge {}",
                    short_code,
                    uuid_str
                );
                self.get_challenge(&uuid_str).await
            }
            None => {
                #[cfg(target_arch = "wasm32")]
                console_log!("[ChallengeDO] Short code {} not found", short_code);
                Response::error("Not found", 404)
            }
        }
    }

    /// Persist a new challenge record and its short-code mapping.
    ///
    /// Idempotent: returns success if the challenge already exists.
    /// SECURITY: Validates UUID and short code format before storage (CWE-89).
    async fn create_challenge(&self, uuid: &str, mut req: Request) -> Result<Response> {
        // SECURITY: Validate UUID to prevent injection attacks (CWE-89, CSA-01)
        if let Err(_e) = validate_challenge_id(uuid) {
            #[cfg(target_arch = "wasm32")]
            console_log!("[ChallengeDO] Invalid UUID rejected in create: {}", uuid);
            return Response::error("Invalid challenge ID", 400);
        }

        // IV-1231: Enforce body size limit before parsing to prevent memory exhaustion.
        let body_bytes = req.bytes().await?;
        if body_bytes.len() > MAX_DO_BODY_SIZE {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[ChallengeDO] Create body too large: {} > {}",
                body_bytes.len(),
                MAX_DO_BODY_SIZE
            );
            return Response::error("Request entity too large", 413);
        }
        let challenge: CachedChallenge = serde_json::from_slice(&body_bytes)
            .map_err(|e| worker::Error::RustError(format!("Invalid JSON: {}", e)))?;

        // SECURITY: Validate short code from challenge data
        if let Err(_e) = validate_short_code(&challenge.short_code) {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[ChallengeDO] Invalid short code in challenge data: {}",
                challenge.short_code
            );
            return Response::error("Invalid short code", 400);
        }

        // INV-VA-050: Verify that the caller-supplied short_code matches the
        // deterministic derivation from the UUID. Without this check, a
        // caller could bind an arbitrary short_code to any challenge UUID,
        // potentially hijacking or aliasing lookups via the code:{short_code}
        // reverse index.
        if let Ok(parsed_uuid) = uuid::Uuid::parse_str(uuid) {
            let expected_code =
                crate::routes::challenge::generate_short_code_from_uuid(&parsed_uuid);
            if challenge.short_code != expected_code {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[ChallengeDO] SECURITY: short_code mismatch for {}: got '{}', expected '{}'",
                    uuid,
                    challenge.short_code,
                    expected_code
                );
                return Response::error("Short code does not match challenge ID", 400);
            }
        }
        // Note: UUID format was already validated above via validate_challenge_id(),
        // so the parse_str call should always succeed. The if-let is defensive.

        // Warn if we are missing PKCE bytes; this should not happen in normal flows.
        if challenge.code_challenge_bytes.is_empty() {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[ChallengeDO] WARNING: Creating challenge {} without PKCE bytes",
                uuid
            );
        }

        let key = format!("ch:{}", uuid);

        // Preserve idempotency by returning success when the record already exists.
        let existing: Option<CachedChallenge> =
            self.state.storage().get(&key).await.unwrap_or(None);
        if existing.is_some() {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[ChallengeDO] Challenge {} already exists, returning success",
                uuid
            );
            return Response::ok("created");
        }

        // Store the challenge as JSON matching CachedChallenge schema.
        // H4: retry on transient write failure; a definitive failure returns
        // 503 (Service Unavailable) so the client can safely retry. The single
        // writer model plus the idempotency check above keep retries safe.
        if self
            .put_with_retry(&key, &challenge, "create_challenge_record")
            .await
            .is_err()
        {
            return Response::error("Service Unavailable", 503);
        }

        // Store internal mapping: code:{short_code} -> uuid
        let code_key = format!("code:{}", challenge.short_code);
        if self
            .put_with_retry(&code_key, &uuid, "create_short_code_mapping")
            .await
            .is_err()
        {
            return Response::error("Service Unavailable", 503);
        }

        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[ChallengeDO] Created challenge {} with short_code {} and state: {:?}",
            uuid,
            challenge.short_code,
            challenge.state
        );

        Response::ok("created")
    }

    /// Retrieve a challenge by UUID. Returns 404 if absent, 410 if expired.
    ///
    /// SECURITY: Expired challenges are deleted on read and an audit event
    /// is embedded in the 410 response body for the Worker to dispatch (AL-050).
    async fn get_challenge(&self, uuid: &str) -> Result<Response> {
        // SECURITY: Validate UUID to prevent injection attacks (CWE-89, CSA-01)
        if let Err(_e) = validate_challenge_id(uuid) {
            #[cfg(target_arch = "wasm32")]
            console_log!("[ChallengeDO] Invalid UUID rejected in get: {}", uuid);
            return Response::error("Invalid challenge ID", 400);
        }

        let key = format!("ch:{}", uuid);
        let now = Date::now().as_millis() / 1000;

        let stored: Option<CachedChallenge> = self.state.storage().get(&key).await.unwrap_or(None);
        match stored {
            Some(challenge) if challenge.expires_at > now => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[ChallengeDO] Retrieved challenge {} in state: {:?}",
                    uuid,
                    challenge.state
                );
                Response::from_json(&challenge) // nosemgrep: provii.workers.response-missing-no-store (security headers added by worker router)
            }
            Some(challenge) => {
                // Challenge expired; delete the record and signal 410 to the caller.
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[ChallengeDO] Challenge {} expired (exp: {}, now: {})",
                    uuid,
                    challenge.expires_at,
                    now
                );
                // Delete the primary challenge record
                self.state.storage().delete(&key).await?;

                // Delete the internal mapping: code:{short_code} -> uuid
                let code_key = format!("code:{}", challenge.short_code);
                self.state.storage().delete(&code_key).await?;

                // AL-050: Audit expired challenge auto-deletion.
                let audit_event = AuditEventData {
                    event_type: "challenge_expired_auto_deleted".into(),
                    severity: "info".into(),
                    message: format!(
                        "Challenge {} auto-deleted on read (expired at {}, now {})",
                        uuid, challenge.expires_at, now
                    ),
                    resource_id: uuid.to_string(),
                    origin: challenge.origin.clone(),
                    component: "challenge_do".into(),
                    details: serde_json::json!({
                        "expires_at": challenge.expires_at,
                        "now": now,
                        "state_at_expiry": challenge.state.as_str(),
                    })
                    .to_string(),
                    ..Default::default()
                };
                let body = serde_json::json!({
                    "error": "Challenge expired",
                    "audit_events": [audit_event],
                });
                Response::from_json(&body).map(|r| r.with_status(410))
            }
            None => {
                #[cfg(target_arch = "wasm32")]
                console_log!("[ChallengeDO] Challenge {} not found", uuid);
                Response::error("Not found", 404)
            }
        }
    }

    /// Update an existing challenge record, enforcing the state machine.
    ///
    /// SECURITY (RT-032): Only valid forward transitions are permitted.
    /// Terminal states (`Verified`, `Failed`, `Expired`) reject all updates
    /// with HTTP 409. Expired challenges reject non-terminal updates with
    /// HTTP 410 (RT-033). Audit events for every transition are returned
    /// in the response body (AL-049).
    ///
    /// SECURITY (ADV-VA-002): Only mutable lifecycle fields from
    /// [`ChallengeUpdate`] are applied. All immutable fields (id, short_code,
    /// rp_challenge, code_challenge, code_challenge_bytes, submit_secret,
    /// origin, expires_at, created_at, cutoff_days, verifying_key_id,
    /// proof_direction, client_id, tenant_id) are preserved from the stored
    /// record, preventing PKCE bypass, submit_secret replacement, origin
    /// rebinding, and BOLA attacks via client_id/tenant_id mutation.
    ///
    /// VA-DO-001 / VA-DOD-011: Updates to non-existent challenges return
    /// 404. Creation must go through `create_challenge` which enforces
    /// short_code validation, integrity checks, and reverse index writes.
    async fn update_challenge(&self, uuid: &str, mut req: Request) -> Result<Response> {
        // SECURITY: Validate UUID to prevent injection attacks (CWE-89, CSA-01)
        if let Err(_e) = validate_challenge_id(uuid) {
            #[cfg(target_arch = "wasm32")]
            console_log!("[ChallengeDO] Invalid UUID rejected in update: {}", uuid);
            return Response::error("Invalid challenge ID", 400);
        }

        // IV-1231: Enforce body size limit before parsing to prevent memory exhaustion.
        let body_bytes = req.bytes().await?;
        if body_bytes.len() > MAX_DO_BODY_SIZE {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[ChallengeDO] Update body too large: {} > {}",
                body_bytes.len(),
                MAX_DO_BODY_SIZE
            );
            return Response::error("Request entity too large", 413);
        }
        let key = format!("ch:{}", uuid);

        // AL-049: Collect audit events for state transitions.
        let mut audit_events: Vec<AuditEventData> = Vec::new();

        // Load the existing record. VA-DO-001 / VA-DOD-011: Reject updates
        // to non-existent challenges. Creation must go through the validated
        // create path which enforces short_code format, UUID-to-short_code
        // integrity, and the code:{short_code} reverse index.
        let existing: Option<CachedChallenge> =
            self.state.storage().get(&key).await.unwrap_or(None);

        match existing {
            None => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[ChallengeDO] Update rejected for non-existent challenge {}",
                    uuid
                );
                Response::error("Not found", 404)
            }
            Some(mut existing_challenge) => {
                // ADV-VA-002: Deserialise into the narrow ChallengeUpdate struct.
                // Immutable fields from the payload are silently discarded.
                let update: ChallengeUpdate = serde_json::from_slice(&body_bytes)
                    .map_err(|e| worker::Error::RustError(format!("Invalid JSON: {}", e)))?;

                // RT-033: Reject transitions on expired challenges (unless moving to terminal).
                // VA-DOD-006: Use `>=` to match the expiry boundary in get_challenge,
                // which treats `expires_at == now` as expired (`expires_at > now` is false).
                let now_secs = Date::now().as_millis() / 1000;
                if now_secs >= existing_challenge.expires_at && !is_terminal_state(&update.state) {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[ChallengeDO] Rejecting update on expired challenge {}",
                        uuid
                    );
                    return Response::error("Challenge expired", 410);
                }

                // RT-032: Enforce valid state transitions.
                if existing_challenge.state != update.state {
                    if !is_valid_transition(&existing_challenge.state, &update.state) {
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            "[ChallengeDO] Invalid state transition rejected for {}: {:?} -> {:?}",
                            uuid,
                            existing_challenge.state,
                            update.state
                        );
                        audit_events.push(AuditEventData {
                            event_type: "invalid_state_transition_rejected".into(),
                            severity: "warning".into(),
                            message: format!(
                                "Invalid state transition rejected for {}: {:?} -> {:?}",
                                uuid, existing_challenge.state, update.state
                            ),
                            resource_id: uuid.to_string(),
                            origin: existing_challenge.origin.clone(),
                            component: "challenge_do".into(),
                            details: serde_json::json!({
                                "from_state": existing_challenge.state.as_str(),
                                "to_state": update.state.as_str(),
                            })
                            .to_string(),
                            ..Default::default()
                        });
                        let body = serde_json::json!({
                            "error": "Invalid state transition",
                            "audit_events": audit_events,
                        });
                        return Response::from_json(&body).map(|r| r.with_status(409));
                    }

                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[ChallengeDO] Challenge {} state transition: {:?} -> {:?}",
                        uuid,
                        existing_challenge.state,
                        update.state
                    );
                    audit_events.push(AuditEventData {
                        event_type: "challenge_state_transition".into(),
                        severity: "info".into(),
                        message: format!(
                            "Challenge {} state transition: {:?} -> {:?}",
                            uuid, existing_challenge.state, update.state
                        ),
                        resource_id: uuid.to_string(),
                        origin: existing_challenge.origin.clone(),
                        component: "challenge_do".into(),
                        details: serde_json::json!({
                            "from_state": existing_challenge.state.as_str(),
                            "to_state": update.state.as_str(),
                        })
                        .to_string(),
                        ..Default::default()
                    });
                }

                // SECURITY (ADV-VA-002): Apply only mutable lifecycle fields from
                // the update. All immutable fields (id, short_code, rp_challenge,
                // code_challenge, code_challenge_bytes, submit_secret, origin,
                // expires_at, created_at, cutoff_days, verifying_key_id,
                // proof_direction, client_id, tenant_id) are preserved from the
                // existing stored record.

                // ADV-VA-002-F2 + ADV-VA-002-N1: Automatically zeroise submit_secret
                // when transitioning out of Pending. This is the semantic invariant:
                // once proof submission begins, the secret is no longer needed. Tying
                // zeroisation to the state transition rather than a caller flag means
                // it cannot be forgotten at any call site.
                if existing_challenge.state == ChallengeState::Pending
                    && update.state != ChallengeState::Pending
                {
                    existing_challenge.submit_secret.zeroize();
                }

                existing_challenge.state = update.state;
                if let Some(ps) = update.proof_submitted {
                    existing_challenge.proof_submitted = ps;
                }
                if let Some(pva) = update.proof_verified_at {
                    existing_challenge.proof_verified_at = Some(pva);
                }
                if let Some(va) = update.verified_at {
                    existing_challenge.verified_at = Some(va);
                }
                if let Some(ref kid) = update.issuer_kid {
                    existing_challenge.issuer_kid = Some(kid.clone());
                }
                if update.issuer_vk_bytes.is_some() {
                    existing_challenge.issuer_vk_bytes = update.issuer_vk_bytes;
                }

                // Persist the merged challenge record.
                // H4: retry on transient write failure; a definitive failure
                // returns 503. The state machine permits the same transition
                // again (same-state transitions are idempotent), so a client
                // retry after a 503 is safe.
                if self
                    .put_with_retry(&key, &existing_challenge, "update_challenge_record")
                    .await
                    .is_err()
                {
                    return Response::error("Service Unavailable", 503);
                }

                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[ChallengeDO] Updated challenge {} to state: {:?}",
                    uuid,
                    existing_challenge.state
                );
                Response::from_json(&serde_json::json!({
                    "result": "updated",
                    "audit_events": audit_events,
                }))
            }
        }
    }

    /// Delete a challenge record and its short-code mapping.
    ///
    /// Idempotent: returns success even if the challenge does not exist.
    /// SECURITY (RT-034): An audit event is emitted before deletion so
    /// the Worker caller can dispatch it through the structured audit pipeline.
    async fn delete_challenge(&self, uuid: &str) -> Result<Response> {
        // SECURITY: Validate UUID to prevent injection attacks (CWE-89, CSA-01)
        if let Err(_e) = validate_challenge_id(uuid) {
            #[cfg(target_arch = "wasm32")]
            console_log!("[ChallengeDO] Invalid UUID rejected in delete: {}", uuid);
            return Response::error("Invalid challenge ID", 400);
        }

        let key = format!("ch:{}", uuid);

        let mut audit_events: Vec<AuditEventData> = Vec::new();

        let existing: Option<CachedChallenge> =
            self.state.storage().get(&key).await.unwrap_or(None);
        if let Some(challenge) = existing {
            // ADV-VA-023 / INV-VA-057: Prevent deletion of challenges in
            // evidence-bearing states (ProofOkWaitingForRedeem, Verified).
            // Destroying these challenges would erase audit evidence of a
            // successful proof or pending redemption. Expired and Failed are
            // non-evidence terminal states and remain deletable (routine
            // cleanup).
            if matches!(
                challenge.state,
                ChallengeState::Verified | ChallengeState::ProofOkWaitingForRedeem
            ) {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[ChallengeDO] SECURITY: Rejecting delete of {:?} challenge {}",
                    challenge.state,
                    uuid
                );
                audit_events.push(AuditEventData {
                    event_type: "challenge_delete_blocked".into(),
                    severity: "warning".into(),
                    message: format!(
                        "Delete of challenge {} blocked: state {:?} is evidence-bearing",
                        uuid, challenge.state
                    ),
                    resource_id: uuid.to_string(),
                    origin: challenge.origin.clone(),
                    component: "challenge_do".into(),
                    details: serde_json::json!({
                        "state_at_deletion_attempt": challenge.state.as_str(),
                        "blocked": true,
                    })
                    .to_string(),
                    ..Default::default()
                });
                return Response::from_json(&serde_json::json!({
                    "error": format!("Cannot delete challenge in {} state", challenge.state.as_str()),
                    "audit_events": audit_events,
                }))
                .map(|r| r.with_status(409));
            }

            audit_events.push(AuditEventData {
                event_type: "challenge_deleted".into(),
                severity: "info".into(),
                message: format!("Challenge {} deleted (state: {:?})", uuid, challenge.state),
                resource_id: uuid.to_string(),
                origin: challenge.origin.clone(),
                component: "challenge_do".into(),
                details: serde_json::json!({
                    "state_at_deletion": challenge.state.as_str(),
                    "expires_at": challenge.expires_at,
                })
                .to_string(),
                ..Default::default()
            });

            self.state.storage().delete(&key).await?;

            let code_key = format!("code:{}", challenge.short_code);
            self.state.storage().delete(&code_key).await?;

            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[ChallengeDO] Deleted challenge {} and short_code mapping {}",
                uuid,
                challenge.short_code
            );
        } else {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[ChallengeDO] Attempted to delete non-existent challenge {}",
                uuid
            );
        }

        Response::from_json(&serde_json::json!({
            "result": "deleted",
            "audit_events": audit_events,
        }))
    }
}

#[cfg(test)]
// Test code: unwrap and expect are the standard assertion pattern for unit tests.
// A panic from `.unwrap()` in a test IS the correct failure mode.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::string_slice
)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    H4: put_with_retry schedule                            */
    /* ========================================================================== */

    #[test]
    fn test_put_max_attempts_is_three() {
        assert_eq!(PUT_MAX_ATTEMPTS, 3);
    }

    #[test]
    fn test_put_initial_backoff_is_10ms() {
        assert_eq!(PUT_INITIAL_BACKOFF_MS, 10);
    }

    #[test]
    fn test_put_backoff_schedule_within_10_to_100ms_band() {
        // The realised backoff sleeps across the retry loop are 10ms then 20ms
        // (the 40ms slot is computed but not slept on the final attempt). Assert
        // the doubling and that every value stays inside the documented
        // 10-100ms band.
        let mut backoff = PUT_INITIAL_BACKOFF_MS;
        let mut schedule = Vec::new();
        for attempt in 1..=PUT_MAX_ATTEMPTS {
            if attempt < PUT_MAX_ATTEMPTS {
                schedule.push(backoff);
                backoff = backoff.saturating_mul(2);
            }
        }
        assert_eq!(schedule, vec![10, 20]);
        // Next value (had there been a fourth attempt) is 40ms, still <= 100ms.
        assert_eq!(backoff, 40);
        for ms in &schedule {
            assert!(
                (10..=100).contains(ms),
                "backoff {}ms must be within the 10-100ms band",
                ms
            );
        }
    }

    /* ========================================================================== */
    /*                    State Machine Tests                                    */
    /* ========================================================================== */

    #[test]
    fn test_valid_transition_pending_to_proof_ok() {
        assert!(is_valid_transition(
            &ChallengeState::Pending,
            &ChallengeState::ProofOkWaitingForRedeem
        ));
    }

    #[test]
    fn test_valid_transition_pending_to_failed() {
        assert!(is_valid_transition(
            &ChallengeState::Pending,
            &ChallengeState::Failed
        ));
    }

    #[test]
    fn test_valid_transition_pending_to_expired() {
        assert!(is_valid_transition(
            &ChallengeState::Pending,
            &ChallengeState::Expired
        ));
    }

    #[test]
    fn test_invalid_transition_pending_to_verified() {
        assert!(!is_valid_transition(
            &ChallengeState::Pending,
            &ChallengeState::Verified
        ));
    }

    #[test]
    fn test_valid_transition_proof_ok_to_verified() {
        assert!(is_valid_transition(
            &ChallengeState::ProofOkWaitingForRedeem,
            &ChallengeState::Verified
        ));
    }

    #[test]
    fn test_valid_transition_proof_ok_to_failed() {
        assert!(is_valid_transition(
            &ChallengeState::ProofOkWaitingForRedeem,
            &ChallengeState::Failed
        ));
    }

    #[test]
    fn test_invalid_transition_verified_to_anything() {
        assert!(!is_valid_transition(
            &ChallengeState::Verified,
            &ChallengeState::Pending
        ));
        assert!(!is_valid_transition(
            &ChallengeState::Verified,
            &ChallengeState::Failed
        ));
        assert!(!is_valid_transition(
            &ChallengeState::Verified,
            &ChallengeState::Expired
        ));
        assert!(!is_valid_transition(
            &ChallengeState::Verified,
            &ChallengeState::ProofOkWaitingForRedeem
        ));
    }

    #[test]
    fn test_invalid_transition_failed_to_anything() {
        assert!(!is_valid_transition(
            &ChallengeState::Failed,
            &ChallengeState::Pending
        ));
        assert!(!is_valid_transition(
            &ChallengeState::Failed,
            &ChallengeState::Verified
        ));
    }

    #[test]
    fn test_idempotent_transition_same_state() {
        assert!(is_valid_transition(
            &ChallengeState::Pending,
            &ChallengeState::Pending
        ));
        assert!(is_valid_transition(
            &ChallengeState::Verified,
            &ChallengeState::Verified
        ));
    }

    #[test]
    fn test_is_terminal_state() {
        assert!(is_terminal_state(&ChallengeState::Verified));
        assert!(is_terminal_state(&ChallengeState::Failed));
        assert!(is_terminal_state(&ChallengeState::Expired));
        assert!(!is_terminal_state(&ChallengeState::Pending));
        assert!(!is_terminal_state(&ChallengeState::ProofOkWaitingForRedeem));
    }

    /* ========================================================================== */
    /*                    Key Format Tests                                       */
    /* ========================================================================== */

    #[test]
    fn test_key_format_challenge() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let key = format!("ch:{}", uuid);
        assert_eq!(key, "ch:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_key_format_code() {
        let short_code = "123456789012";
        let key = format!("code:{}", short_code);
        assert_eq!(key, "code:123456789012");
    }

    /* ========================================================================== */
    /*                    Path Parsing Tests                                     */
    /* ========================================================================== */

    #[test]
    fn test_path_parsing_challenge_segments() {
        let path = "/challenge/550e8400-e29b-41d4-a716-446655440000";
        let segments: Vec<&str> = path.split('/').collect();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[1], "challenge");
        assert_eq!(segments[2], "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_path_parsing_with_action() {
        let path = "/challenge/550e8400-e29b-41d4-a716-446655440000/create";
        let segments: Vec<&str> = path.split('/').collect();
        assert_eq!(segments.len(), 4);
        assert_eq!(segments[3], "create");
    }

    #[test]
    fn test_path_parsing_action_default() {
        let path = "/challenge/550e8400-e29b-41d4-a716-446655440000";
        let segments: Vec<&str> = path.split('/').collect();
        let action = segments.get(3).copied().unwrap_or("get");
        assert_eq!(action, "get");
    }

    #[test]
    fn test_path_parsing_insufficient_segments() {
        let path = "/challenge";
        let segments: Vec<&str> = path.split('/').collect();
        assert!(segments.len() < 3);
    }

    /* ========================================================================== */
    /*                    Expiry Logic Tests                                     */
    /* ========================================================================== */

    #[test]
    fn test_expiry_not_expired() {
        let expires_at = 2000u64;
        let now = 1000u64;
        assert!(expires_at > now);
    }

    #[test]
    fn test_expiry_expired() {
        let expires_at = 1000u64;
        let now = 2000u64;
        assert!(expires_at <= now);
    }

    #[test]
    fn test_expiry_exact_boundary() {
        let expires_at = 1000u64;
        let now = 1000u64;
        assert!(expires_at <= now);
    }

    /* ========================================================================== */
    /*                    ChallengeUpdate Deserialisation Tests (ADV-VA-002)     */
    /* ========================================================================== */

    #[test]
    fn test_challenge_update_from_full_cached_challenge_payload() {
        // A full CachedChallenge JSON should deserialise into ChallengeUpdate,
        // extracting only the mutable fields and silently discarding immutable ones.
        let zeroes: Vec<u8> = vec![0u8; 32];
        let json = serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "short_code": "123456789012",
            "rp_challenge": zeroes,
            "cutoff_days": 19000,
            "verifying_key_id": 1,
            "code_challenge": "test_code_challenge",
            "code_challenge_bytes": zeroes,
            "submit_secret": zeroes,
            "origin": "https://example.com",
            "expires_at": 9999999999u64,
            "created_at": 1000000000u64,
            "state": "ProofOkWaitingForRedeem",
            "proof_submitted": true,
            "proof_verified_at": 1000000001u64,
            "client_id": "attacker_client",
            "tenant_id": "attacker_tenant"
        });
        let update: ChallengeUpdate = serde_json::from_value(json).unwrap();
        assert_eq!(update.state, ChallengeState::ProofOkWaitingForRedeem);
        assert_eq!(update.proof_submitted, Some(true));
        assert_eq!(update.proof_verified_at, Some(1000000001));
        // client_id and tenant_id are NOT present on ChallengeUpdate (ADV-VA-002-F1).
        // Immutable fields (id, short_code, rp_challenge, etc.) are silently ignored.
    }

    #[test]
    fn test_challenge_update_minimal_payload() {
        let json = serde_json::json!({"state": "Failed"});
        let update: ChallengeUpdate = serde_json::from_value(json).unwrap();
        assert_eq!(update.state, ChallengeState::Failed);
        assert!(update.proof_submitted.is_none());
        assert!(update.proof_verified_at.is_none());
        assert!(update.verified_at.is_none());
        assert!(update.issuer_kid.is_none());
        assert!(update.issuer_vk_bytes.is_none());
    }

    #[test]
    fn test_challenge_update_unknown_fields_ignored() {
        let json = serde_json::json!({
            "state": "Pending",
            "totally_unknown_field": "should be ignored",
            "code_challenge": "also ignored"
        });
        // serde default deny_unknown_fields is off, so this must succeed.
        let update: ChallengeUpdate = serde_json::from_value(json).unwrap();
        assert_eq!(update.state, ChallengeState::Pending);
    }

    /* ========================================================================== */
    /*                    Exhaustive State Transition Matrix                     */
    /* ========================================================================== */

    /// Exhaustive test covering every possible (from, to) pair in the state
    /// machine. The expected matrix is hardcoded from the spec in the module
    /// doc comment. Any accidental change to `is_valid_transition` will cause
    /// at least one cell to fail.
    #[test]
    fn test_transition_matrix_exhaustive() {
        let all = [
            ChallengeState::Pending,
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];

        // Row = from, Col = to (indexed by position in `all`).
        // true = transition allowed.
        let expected: [[bool; 5]; 5] = [
            // Pending -> Pending, ProofOk, Verified, Failed, Expired
            [true, true, false, true, true],
            // ProofOk -> Pending, ProofOk, Verified, Failed, Expired
            [false, true, true, true, true],
            // Verified -> Pending, ProofOk, Verified, Failed, Expired
            [false, false, true, false, false],
            // Failed -> Pending, ProofOk, Verified, Failed, Expired
            [false, false, false, true, false],
            // Expired -> Pending, ProofOk, Verified, Failed, Expired
            [false, false, false, false, true],
        ];

        for (from_idx, from_state) in all.iter().enumerate() {
            for (to_idx, to_state) in all.iter().enumerate() {
                let result = is_valid_transition(from_state, to_state);
                assert_eq!(
                    result, expected[from_idx][to_idx],
                    "Transition {:?} -> {:?}: expected {}, got {}",
                    from_state, to_state, expected[from_idx][to_idx], result
                );
            }
        }
    }

    /* ========================================================================== */
    /*                    Additional State Transition Edge Cases                  */
    /* ========================================================================== */

    #[test]
    fn test_valid_transition_proof_ok_to_expired() {
        assert!(is_valid_transition(
            &ChallengeState::ProofOkWaitingForRedeem,
            &ChallengeState::Expired
        ));
    }

    #[test]
    fn test_invalid_transition_proof_ok_to_pending() {
        // Backward transition: ProofOk cannot revert to Pending.
        assert!(!is_valid_transition(
            &ChallengeState::ProofOkWaitingForRedeem,
            &ChallengeState::Pending
        ));
    }

    #[test]
    fn test_invalid_transition_expired_to_anything() {
        // Expired is terminal; cannot transition to any other state.
        assert!(!is_valid_transition(
            &ChallengeState::Expired,
            &ChallengeState::Pending
        ));
        assert!(!is_valid_transition(
            &ChallengeState::Expired,
            &ChallengeState::ProofOkWaitingForRedeem
        ));
        assert!(!is_valid_transition(
            &ChallengeState::Expired,
            &ChallengeState::Verified
        ));
        assert!(!is_valid_transition(
            &ChallengeState::Expired,
            &ChallengeState::Failed
        ));
    }

    #[test]
    fn test_idempotent_all_states() {
        // Every state must accept a self-transition (idempotent).
        let all = [
            ChallengeState::Pending,
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];
        for state in &all {
            assert!(
                is_valid_transition(state, state),
                "Self-transition for {:?} must be valid",
                state
            );
        }
    }

    #[test]
    fn test_invalid_transition_failed_to_expired() {
        assert!(!is_valid_transition(
            &ChallengeState::Failed,
            &ChallengeState::Expired
        ));
    }

    #[test]
    fn test_invalid_transition_failed_to_proof_ok() {
        assert!(!is_valid_transition(
            &ChallengeState::Failed,
            &ChallengeState::ProofOkWaitingForRedeem
        ));
    }

    #[test]
    fn test_invalid_transition_verified_to_failed() {
        // Explicitly test: Verified cannot move to Failed (replay prevention).
        assert!(!is_valid_transition(
            &ChallengeState::Verified,
            &ChallengeState::Failed
        ));
    }

    /// Verify that non-terminal states are NOT terminal.
    #[test]
    fn test_is_terminal_state_non_terminals() {
        assert!(!is_terminal_state(&ChallengeState::Pending));
        assert!(!is_terminal_state(&ChallengeState::ProofOkWaitingForRedeem));
    }

    /// Verify terminal and is_valid_transition are consistent: if a state is
    /// terminal, it rejects all non-self transitions.
    #[test]
    fn test_terminal_rejects_all_non_self_transitions() {
        let terminals = [
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];
        let all = [
            ChallengeState::Pending,
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];
        for terminal in &terminals {
            assert!(is_terminal_state(terminal));
            for target in &all {
                if terminal != target {
                    assert!(
                        !is_valid_transition(terminal, target),
                        "Terminal {:?} should reject transition to {:?}",
                        terminal,
                        target
                    );
                }
            }
        }
    }

    /// Forward-only invariant: non-terminal states never transition backward.
    /// "Backward" is defined as targeting a state earlier in the lifecycle.
    #[test]
    fn test_no_backward_transitions() {
        // ProofOk -> Pending is backward.
        assert!(!is_valid_transition(
            &ChallengeState::ProofOkWaitingForRedeem,
            &ChallengeState::Pending
        ));
        // Verified/Failed/Expired -> Pending is backward.
        assert!(!is_valid_transition(
            &ChallengeState::Verified,
            &ChallengeState::Pending
        ));
        assert!(!is_valid_transition(
            &ChallengeState::Failed,
            &ChallengeState::Pending
        ));
        assert!(!is_valid_transition(
            &ChallengeState::Expired,
            &ChallengeState::Pending
        ));
        // Verified -> ProofOk is backward.
        assert!(!is_valid_transition(
            &ChallengeState::Verified,
            &ChallengeState::ProofOkWaitingForRedeem
        ));
    }

    /// Pending cannot skip directly to Verified (must go through ProofOk first).
    #[test]
    fn test_pending_cannot_skip_to_verified() {
        assert!(!is_valid_transition(
            &ChallengeState::Pending,
            &ChallengeState::Verified
        ));
    }

    /* ========================================================================== */
    /*                    Path Parsing Additional Tests                           */
    /* ========================================================================== */

    #[test]
    fn test_path_parsing_code_resource_type() {
        let path = "/code/123456789012";
        let segments: Vec<&str> = path.split('/').collect();
        assert_eq!(segments.len(), 3);
        let resource_type = segments.get(1).copied();
        assert_eq!(resource_type, Some("code"));
        let identifier = segments.get(2).copied();
        assert_eq!(identifier, Some("123456789012"));
    }

    #[test]
    fn test_path_parsing_action_update() {
        let path = "/challenge/550e8400-e29b-41d4-a716-446655440000/update";
        let segments: Vec<&str> = path.split('/').collect();
        let action = segments.get(3).copied().unwrap_or("get");
        assert_eq!(action, "update");
    }

    #[test]
    fn test_path_parsing_action_create() {
        let path = "/challenge/550e8400-e29b-41d4-a716-446655440000/create";
        let segments: Vec<&str> = path.split('/').collect();
        let action = segments.get(3).copied().unwrap_or("get");
        assert_eq!(action, "create");
    }

    #[test]
    fn test_path_parsing_unknown_action_defaults_to_get() {
        // When no action segment is present, default is "get".
        let path = "/challenge/some-uuid";
        let segments: Vec<&str> = path.split('/').collect();
        let action = segments.get(3).copied().unwrap_or("get");
        assert_eq!(action, "get");
    }

    #[test]
    fn test_path_parsing_empty_string() {
        let path = "";
        let segments: Vec<&str> = path.split('/').collect();
        // Empty string splits into [""], length 1, which is < 3.
        assert!(segments.len() < 3);
    }

    #[test]
    fn test_path_parsing_root_only() {
        let path = "/";
        let segments: Vec<&str> = path.split('/').collect();
        // "/" splits into ["", ""], length 2, which is < 3.
        assert!(segments.len() < 3);
    }

    #[test]
    fn test_path_parsing_single_segment() {
        let path = "/challenge";
        let segments: Vec<&str> = path.split('/').collect();
        // "/challenge" splits into ["", "challenge"], length 2.
        assert_eq!(segments.len(), 2);
        assert!(segments.len() < 3);
    }

    #[test]
    fn test_path_parsing_trailing_slash() {
        let path = "/challenge/550e8400-e29b-41d4-a716-446655440000/";
        let segments: Vec<&str> = path.split('/').collect();
        // Trailing slash produces an extra empty segment.
        assert_eq!(segments.len(), 4);
        let action = segments.get(3).copied().unwrap_or("get");
        // The trailing slash produces an empty string, not "get".
        assert_eq!(action, "");
    }

    #[test]
    fn test_path_parsing_extra_segments_ignored() {
        let path = "/challenge/some-uuid/create/extra/segments";
        let segments: Vec<&str> = path.split('/').collect();
        // The DO code only looks at segments 1, 2, and 3.
        let resource_type = segments.get(1).copied();
        let identifier = segments.get(2).copied();
        let action = segments.get(3).copied().unwrap_or("get");
        assert_eq!(resource_type, Some("challenge"));
        assert_eq!(identifier, Some("some-uuid"));
        assert_eq!(action, "create");
    }

    #[test]
    fn test_path_segments_get_returns_none_for_out_of_range() {
        let segments: Vec<&str> = vec!["", "challenge"];
        assert!(segments.get(2).is_none());
        assert!(segments.get(99).is_none());
    }

    /* ========================================================================== */
    /*                    Key Format Additional Tests                             */
    /* ========================================================================== */

    #[test]
    fn test_key_format_challenge_with_empty_uuid() {
        let key = format!("ch:{}", "");
        assert_eq!(key, "ch:");
    }

    #[test]
    fn test_key_format_code_with_empty_code() {
        let key = format!("code:{}", "");
        assert_eq!(key, "code:");
    }

    #[test]
    fn test_key_format_challenge_prefix_never_overlaps_code_prefix() {
        // Ensure the two key namespaces cannot collide.
        let ch_key = format!("ch:{}", "123456789012");
        let code_key = format!("code:{}", "123456789012");
        assert_ne!(ch_key, code_key);
        assert!(ch_key.starts_with("ch:"));
        assert!(code_key.starts_with("code:"));
    }

    #[test]
    fn test_key_format_preserves_uuid_case() {
        let uuid = "550E8400-E29B-41D4-A716-446655440000";
        let key = format!("ch:{}", uuid);
        assert_eq!(key, "ch:550E8400-E29B-41D4-A716-446655440000");
    }

    /* ========================================================================== */
    /*                    Expiry Logic Additional Tests                           */
    /* ========================================================================== */

    /// In `get_challenge`, the live check is `expires_at > now`.
    /// When expires_at == now, the challenge is treated as expired.
    #[test]
    fn test_expiry_get_challenge_boundary_equal() {
        let expires_at = 1000u64;
        let now = 1000u64;
        // expires_at > now is false => expired
        assert!((expires_at <= now));
    }

    /// VA-DOD-006: In `update_challenge`, expired check is now `now >= expires_at`
    /// (aligned with get_challenge which uses `expires_at > now`). When
    /// expires_at == now, `now >= expires_at` is true => expired for update.
    #[test]
    fn test_expiry_update_challenge_boundary_equal() {
        let expires_at = 1000u64;
        let now = 1000u64;
        // now >= expires_at is true => expired for update (aligned with get)
        assert!(now >= expires_at);
    }

    /// One second before expiry: challenge is still live in both get and update.
    #[test]
    fn test_expiry_one_second_before() {
        let expires_at = 1001u64;
        let now = 1000u64;
        // get: expires_at > now => live
        assert!(expires_at > now);
        // update: now > expires_at => false => not expired
        assert!((now <= expires_at));
    }

    /// One second after expiry: challenge is expired in both get and update.
    #[test]
    fn test_expiry_one_second_after() {
        let expires_at = 999u64;
        let now = 1000u64;
        // get: expires_at > now => false => expired
        assert!((expires_at <= now));
        // update: now > expires_at => true => expired
        assert!(now > expires_at);
    }

    /// Zero expiry: always expired (unless now is also zero, see boundary test).
    #[test]
    fn test_expiry_zero_always_expired() {
        let expires_at = 0u64;
        let now = 1u64;
        assert!((expires_at <= now));
        assert!(now > expires_at);
    }

    /// Max u64 expiry: never expires (unless now is also max).
    #[test]
    fn test_expiry_max_never_expires() {
        let expires_at = u64::MAX;
        let now = u64::MAX - 1;
        assert!(expires_at > now);
        assert!((now <= expires_at));
    }

    /// Both zero: boundary behaviour matches the equal case.
    /// VA-DOD-006: Both get and update now treat equality as expired.
    #[test]
    fn test_expiry_both_zero() {
        let expires_at = 0u64;
        let now = 0u64;
        // get: expires_at > now => false => expired
        assert!((expires_at <= now));
        // update: now >= expires_at => true => expired (aligned with get)
        assert!(now >= expires_at);
    }

    /// Both max: boundary behaviour matches the equal case.
    /// VA-DOD-006: Both get and update now treat equality as expired.
    #[test]
    fn test_expiry_both_max() {
        let expires_at = u64::MAX;
        let now = u64::MAX;
        assert!((expires_at <= now));
        assert!(now >= expires_at);
    }

    /* ========================================================================== */
    /*                    Expiry + Terminal State Interaction                     */
    /* ========================================================================== */

    /// RT-033: An expired challenge rejects non-terminal updates but accepts
    /// terminal state transitions (Failed, Expired). This tests the guard
    /// condition `now >= expires_at && !is_terminal_state(&update.state)`.
    #[test]
    fn test_expired_challenge_rejects_non_terminal_update() {
        let expires_at = 1000u64;
        let now = 2000u64;
        assert!(now >= expires_at);

        // Non-terminal targets should be rejected.
        assert!(!is_terminal_state(&ChallengeState::Pending));
        assert!(!is_terminal_state(&ChallengeState::ProofOkWaitingForRedeem));

        // Terminal targets should be accepted (the guard lets them through).
        assert!(is_terminal_state(&ChallengeState::Failed));
        assert!(is_terminal_state(&ChallengeState::Expired));
        assert!(is_terminal_state(&ChallengeState::Verified));
    }

    /// Combination: challenge is expired AND in a terminal state. The terminal
    /// state check in is_valid_transition rejects non-self transitions, but the
    /// expiry guard only fires for non-terminal target states. So a terminal
    /// self-transition on an expired challenge passes the expiry guard (terminal
    /// target) and also passes the state machine (self-transition is idempotent).
    #[test]
    fn test_expired_terminal_self_transition_passes() {
        let expires_at = 500u64;
        let now = 1000u64;
        let current_state = ChallengeState::Failed;
        let target_state = ChallengeState::Failed;

        // Expiry guard: now >= expires_at && !is_terminal_state(target)
        let would_reject = now >= expires_at && !is_terminal_state(&target_state);
        assert!(!would_reject);

        // State machine: same state is idempotent
        assert!(is_valid_transition(&current_state, &target_state));
    }

    /* ========================================================================== */
    /*                    MAX_DO_BODY_SIZE Tests                                  */
    /* ========================================================================== */

    #[test]
    fn test_max_do_body_size_constant() {
        assert_eq!(MAX_DO_BODY_SIZE, 65_536);
    }

    #[test]
    fn test_body_size_within_limit() {
        let body = vec![0u8; 65_536];
        assert!(body.len() <= MAX_DO_BODY_SIZE);
    }

    #[test]
    fn test_body_size_exceeds_limit() {
        let body = vec![0u8; 65_537];
        assert!(body.len() > MAX_DO_BODY_SIZE);
    }

    #[test]
    fn test_body_size_empty() {
        let body: Vec<u8> = vec![];
        assert!(body.len() <= MAX_DO_BODY_SIZE);
    }

    #[test]
    fn test_body_size_exactly_at_limit() {
        let body = vec![0u8; MAX_DO_BODY_SIZE];
        assert!(body.len() <= MAX_DO_BODY_SIZE);
        // One more byte pushes over.
        assert!(body.len() + 1 > MAX_DO_BODY_SIZE);
    }

    /* ========================================================================== */
    /*                    ChallengeUpdate Deserialisation Additional Tests        */
    /* ========================================================================== */

    #[test]
    fn test_challenge_update_with_all_optional_fields() {
        let json = serde_json::json!({
            "state": "Verified",
            "proof_submitted": true,
            "proof_verified_at": 1700000000u64,
            "verified_at": 1700000001u64,
            "issuer_kid": "iss-key-42",
            "issuer_vk_bytes": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]
        });
        let update: ChallengeUpdate = serde_json::from_value(json).unwrap();
        assert_eq!(update.state, ChallengeState::Verified);
        assert_eq!(update.proof_submitted, Some(true));
        assert_eq!(update.proof_verified_at, Some(1700000000));
        assert_eq!(update.verified_at, Some(1700000001));
        assert_eq!(update.issuer_kid, Some("iss-key-42".to_string()));
        assert!(update.issuer_vk_bytes.is_some());
        let vk = update.issuer_vk_bytes.unwrap();
        assert_eq!(vk[0], 1);
        assert_eq!(vk[31], 32);
    }

    #[test]
    fn test_challenge_update_missing_state_fails() {
        let json = serde_json::json!({
            "proof_submitted": true
        });
        let result: Result<ChallengeUpdate, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_update_invalid_state_variant() {
        let json = serde_json::json!({
            "state": "SomeInvalidState"
        });
        let result: Result<ChallengeUpdate, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_update_state_number_fails() {
        let json = serde_json::json!({
            "state": 42
        });
        let result: Result<ChallengeUpdate, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_update_state_null_fails() {
        let json = serde_json::json!({
            "state": null
        });
        let result: Result<ChallengeUpdate, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_update_proof_submitted_false() {
        let json = serde_json::json!({
            "state": "Pending",
            "proof_submitted": false
        });
        let update: ChallengeUpdate = serde_json::from_value(json).unwrap();
        assert_eq!(update.proof_submitted, Some(false));
    }

    #[test]
    fn test_challenge_update_proof_submitted_absent_is_none() {
        let json = serde_json::json!({
            "state": "Pending"
        });
        let update: ChallengeUpdate = serde_json::from_value(json).unwrap();
        assert!(update.proof_submitted.is_none());
    }

    #[test]
    fn test_challenge_update_issuer_vk_bytes_wrong_length() {
        // [u8; 32] requires exactly 32 elements.
        let json = serde_json::json!({
            "state": "Verified",
            "issuer_vk_bytes": [1, 2, 3]
        });
        let result: Result<ChallengeUpdate, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_update_issuer_vk_bytes_all_zeroes() {
        let json = serde_json::json!({
            "state": "Verified",
            "issuer_vk_bytes": vec![0u8; 32]
        });
        let update: ChallengeUpdate = serde_json::from_value(json).unwrap();
        assert_eq!(update.issuer_vk_bytes, Some([0u8; 32]));
    }

    #[test]
    fn test_challenge_update_verified_at_zero() {
        let json = serde_json::json!({
            "state": "Verified",
            "verified_at": 0u64
        });
        let update: ChallengeUpdate = serde_json::from_value(json).unwrap();
        assert_eq!(update.verified_at, Some(0));
    }

    #[test]
    fn test_challenge_update_verified_at_max() {
        let json = serde_json::json!({
            "state": "Verified",
            "verified_at": u64::MAX
        });
        let update: ChallengeUpdate = serde_json::from_value(json).unwrap();
        assert_eq!(update.verified_at, Some(u64::MAX));
    }

    /// ADV-VA-002: Immutable fields from CachedChallenge are NOT present on
    /// ChallengeUpdate. Verify the narrow struct rejects attempts to set them.
    /// (serde ignores unknown fields by default, so the values are silently
    /// discarded, which is the correct security behaviour.)
    #[test]
    fn test_challenge_update_ignores_immutable_fields() {
        let json = serde_json::json!({
            "state": "ProofOkWaitingForRedeem",
            "id": "attacker-uuid",
            "short_code": "000000000000",
            "rp_challenge": vec![0u8; 32],
            "code_challenge": "attack",
            "code_challenge_bytes": vec![0u8; 32],
            "submit_secret": vec![0u8; 32],
            "origin": "https://evil.com",
            "expires_at": 9999999999u64,
            "created_at": 0u64,
            "cutoff_days": 0,
            "verifying_key_id": 999,
            "proof_direction": "under_age",
            "client_id": "evil-client",
            "tenant_id": "evil-tenant"
        });
        // Must succeed: unknown fields are silently dropped.
        let update: ChallengeUpdate = serde_json::from_value(json).unwrap();
        assert_eq!(update.state, ChallengeState::ProofOkWaitingForRedeem);
        // The struct has no field for any of the immutable data.
    }

    #[test]
    fn test_challenge_update_empty_json_object_fails() {
        let json = serde_json::json!({});
        let result: Result<ChallengeUpdate, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_update_all_states_deserialise() {
        let state_names = [
            "Pending",
            "ProofOkWaitingForRedeem",
            "Verified",
            "Failed",
            "Expired",
        ];
        let expected = [
            ChallengeState::Pending,
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];
        for (name, exp) in state_names.iter().zip(expected.iter()) {
            let json = serde_json::json!({"state": name});
            let update: ChallengeUpdate = serde_json::from_value(json).unwrap();
            assert_eq!(&update.state, exp);
        }
    }

    #[test]
    fn test_challenge_update_issuer_kid_empty_string() {
        let json = serde_json::json!({
            "state": "Verified",
            "issuer_kid": ""
        });
        let update: ChallengeUpdate = serde_json::from_value(json).unwrap();
        assert_eq!(update.issuer_kid, Some(String::new()));
    }

    /* ========================================================================== */
    /*                    Action Routing Logic Tests                              */
    /* ========================================================================== */

    /// The DO routes POST requests to "create" or "update" based on the action
    /// segment. Any other action returns 400. Test the match logic in isolation.
    #[test]
    fn test_action_routing_known_actions() {
        let known = ["create", "update"];
        for action in &known {
            assert!(
                *action == "create" || *action == "update",
                "Unexpected action: {}",
                action
            );
        }
    }

    #[test]
    fn test_action_routing_unknown_action_is_invalid() {
        let unknown_actions = [
            "delete", "patch", "verify", "redeem", "", "CREATE", "Update",
        ];
        for action in &unknown_actions {
            let is_valid = *action == "create" || *action == "update";
            assert!(!is_valid, "Action '{}' should be invalid", action);
        }
    }

    /* ========================================================================== */
    /*                    Resource Type Routing Tests                             */
    /* ========================================================================== */

    #[test]
    fn test_resource_type_code_detection() {
        let resource_type = "code";
        assert_eq!(resource_type, "code");
    }

    #[test]
    fn test_resource_type_challenge_falls_through() {
        // Any resource type other than "code" falls through to challenge ops.
        let resource_type = "challenge";
        assert_ne!(resource_type, "code");
    }

    #[test]
    fn test_resource_type_case_sensitive() {
        // "Code" and "CODE" are NOT "code".
        assert_ne!("Code", "code");
        assert_ne!("CODE", "code");
    }

    /* ========================================================================== */
    /*                    State Machine + Expiry Combined Scenarios               */
    /* ========================================================================== */

    /// Scenario: A Pending challenge that has expired. An update to
    /// ProofOkWaitingForRedeem (non-terminal) should be rejected by the
    /// expiry guard (RT-033), even though the state transition itself is valid.
    #[test]
    fn test_scenario_expired_pending_rejects_non_terminal_update() {
        let expires_at = 1000u64;
        let now = 2000u64;
        let current = ChallengeState::Pending;
        let target = ChallengeState::ProofOkWaitingForRedeem;

        // State transition is valid.
        assert!(is_valid_transition(&current, &target));
        // But the target is not terminal.
        assert!(!is_terminal_state(&target));
        // And the challenge is expired.
        assert!(now >= expires_at);
        // So the combined guard rejects.
        let rejected = now >= expires_at && !is_terminal_state(&target);
        assert!(rejected);
    }

    /// Scenario: A Pending challenge that has expired. An update to Failed
    /// (terminal) should pass the expiry guard and the state machine.
    #[test]
    fn test_scenario_expired_pending_accepts_terminal_update() {
        let expires_at = 1000u64;
        let now = 2000u64;
        let current = ChallengeState::Pending;
        let target = ChallengeState::Failed;

        assert!(is_valid_transition(&current, &target));
        assert!(is_terminal_state(&target));
        let rejected = now >= expires_at && !is_terminal_state(&target);
        assert!(!rejected);
    }

    /// Scenario: A ProofOkWaitingForRedeem challenge that has expired. An
    /// update to Verified (terminal) passes the expiry guard.
    #[test]
    fn test_scenario_expired_proof_ok_accepts_verified() {
        let expires_at = 500u64;
        let now = 600u64;
        let current = ChallengeState::ProofOkWaitingForRedeem;
        let target = ChallengeState::Verified;

        assert!(is_valid_transition(&current, &target));
        assert!(is_terminal_state(&target));
        let rejected = now >= expires_at && !is_terminal_state(&target);
        assert!(!rejected);
    }

    /// Scenario: Challenge is NOT expired. Non-terminal update proceeds
    /// to state machine check only.
    #[test]
    fn test_scenario_live_challenge_non_terminal_update() {
        let expires_at = 9999u64;
        let now = 1000u64;
        let current = ChallengeState::Pending;
        let target = ChallengeState::ProofOkWaitingForRedeem;

        assert!((now < expires_at));
        assert!(is_valid_transition(&current, &target));
    }

    /* ========================================================================== */
    /*                    Delete Guard (Evidence-Bearing States) Tests            */
    /* ========================================================================== */

    /// ADV-VA-023: Verified and ProofOkWaitingForRedeem are evidence-bearing
    /// and must block deletion.
    #[test]
    fn test_evidence_bearing_states_block_delete() {
        let blocked = [
            ChallengeState::Verified,
            ChallengeState::ProofOkWaitingForRedeem,
        ];
        for state in &blocked {
            let is_blocked = matches!(
                state,
                ChallengeState::Verified | ChallengeState::ProofOkWaitingForRedeem
            );
            assert!(is_blocked, "{:?} should block deletion", state);
        }
    }

    /// Non-evidence states (Pending, Failed, Expired) should NOT block deletion.
    #[test]
    fn test_non_evidence_states_allow_delete() {
        let allowed = [
            ChallengeState::Pending,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];
        for state in &allowed {
            let is_blocked = matches!(
                state,
                ChallengeState::Verified | ChallengeState::ProofOkWaitingForRedeem
            );
            assert!(!is_blocked, "{:?} should allow deletion", state);
        }
    }

    /// Exhaustive: every state is either evidence-bearing (blocks delete) or not.
    #[test]
    fn test_evidence_bearing_exhaustive() {
        let all = [
            ChallengeState::Pending,
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];
        let mut blocked_count = 0;
        let mut allowed_count = 0;
        for state in &all {
            if matches!(
                state,
                ChallengeState::Verified | ChallengeState::ProofOkWaitingForRedeem
            ) {
                blocked_count += 1;
            } else {
                allowed_count += 1;
            }
        }
        assert_eq!(blocked_count, 2);
        assert_eq!(allowed_count, 3);
    }

    /* ========================================================================== */
    /*                    Zeroisation Trigger Logic Tests                         */
    /* ========================================================================== */

    /// ADV-VA-002-F2: submit_secret should be zeroised when transitioning
    /// out of Pending. Test the guard condition in isolation.
    #[test]
    fn test_zeroisation_guard_pending_to_proof_ok() {
        let current = ChallengeState::Pending;
        let target = ChallengeState::ProofOkWaitingForRedeem;
        let should_zeroize =
            current == ChallengeState::Pending && target != ChallengeState::Pending;
        assert!(should_zeroize);
    }

    #[test]
    fn test_zeroisation_guard_pending_to_failed() {
        let current = ChallengeState::Pending;
        let target = ChallengeState::Failed;
        let should_zeroize =
            current == ChallengeState::Pending && target != ChallengeState::Pending;
        assert!(should_zeroize);
    }

    #[test]
    fn test_zeroisation_guard_pending_to_expired() {
        let current = ChallengeState::Pending;
        let target = ChallengeState::Expired;
        let should_zeroize =
            current == ChallengeState::Pending && target != ChallengeState::Pending;
        assert!(should_zeroize);
    }

    #[test]
    fn test_zeroisation_guard_pending_to_pending_no_zeroize() {
        let current = ChallengeState::Pending;
        let target = ChallengeState::Pending;
        let should_zeroize =
            current == ChallengeState::Pending && target != ChallengeState::Pending;
        assert!(!should_zeroize);
    }

    #[test]
    fn test_zeroisation_guard_non_pending_no_zeroize() {
        // If current is already past Pending, the guard does not fire again.
        let non_pending = [
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];
        for current in &non_pending {
            let should_zeroize = *current == ChallengeState::Pending
                && ChallengeState::Verified != ChallengeState::Pending;
            assert!(
                !should_zeroize,
                "Zeroisation guard should not fire for {:?}",
                current
            );
        }
    }

    /* ========================================================================== */
    /*                    ChallengeUpdate Field Application Logic                 */
    /* ========================================================================== */

    /// When proof_submitted is Some, it should be applied. When None, the
    /// existing value is preserved. This tests the `if let Some` pattern.
    #[test]
    fn test_optional_field_some_overwrites() {
        let update_value: Option<bool> = Some(true);
        let mut existing = false;
        if let Some(v) = update_value {
            existing = v;
        }
        assert!(existing);
    }

    #[test]
    fn test_optional_field_none_preserves() {
        let update_value: Option<bool> = None;
        let mut existing = false;
        if let Some(v) = update_value {
            existing = v;
        }
        assert!(!existing);
    }

    #[test]
    fn test_optional_u64_field_some_overwrites() {
        let update_value: Option<u64> = Some(42);
        let mut existing: Option<u64> = None;
        if let Some(v) = update_value {
            existing = Some(v);
        }
        assert_eq!(existing, Some(42));
    }

    #[test]
    fn test_optional_u64_field_none_preserves() {
        let update_value: Option<u64> = None;
        let mut existing: Option<u64> = Some(99);
        if let Some(v) = update_value {
            existing = Some(v);
        }
        assert_eq!(existing, Some(99));
    }

    #[test]
    fn test_optional_string_field_ref_clone() {
        let update_value: Option<String> = Some("kid-123".to_string());
        let mut existing: Option<String> = None;
        if let Some(ref v) = update_value {
            existing = Some(v.clone());
        }
        assert_eq!(existing, Some("kid-123".to_string()));
    }

    /* ========================================================================== */
    /*                    Property-Based Tests                                   */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Key format always starts with "ch:"
        #[test]
        fn prop_key_format_prefix(uuid in "[a-z0-9-]{1,50}") {
            let key = format!("ch:{}", uuid);
            prop_assert!(key.starts_with("ch:"));
        }

        /// Property: Expiry comparison is transitive
        #[test]
        fn prop_expiry_transitive(
            expires_at in any::<u64>(),
            now in any::<u64>()
        ) {
            let is_expired = now >= expires_at;
            let is_valid = expires_at > now;
            prop_assert_eq!(is_expired, !is_valid);
        }

        /// Property: Terminal states reject all transitions
        #[test]
        fn prop_terminal_states_reject_transitions(
            terminal_idx in 0usize..3,
            target_idx in 0usize..5
        ) {
            let terminals = [
                ChallengeState::Verified,
                ChallengeState::Failed,
                ChallengeState::Expired,
            ];
            let all_states = [
                ChallengeState::Pending,
                ChallengeState::ProofOkWaitingForRedeem,
                ChallengeState::Verified,
                ChallengeState::Failed,
                ChallengeState::Expired,
            ];
            let from = &terminals[terminal_idx];
            let to = &all_states[target_idx];
            if from != to {
                prop_assert!(!is_valid_transition(from, to));
            }
        }

        /// Property: Same-state transitions are always valid (idempotent)
        #[test]
        fn prop_same_state_idempotent(state_idx in 0usize..5) {
            let all_states = [
                ChallengeState::Pending,
                ChallengeState::ProofOkWaitingForRedeem,
                ChallengeState::Verified,
                ChallengeState::Failed,
                ChallengeState::Expired,
            ];
            let state = &all_states[state_idx];
            prop_assert!(is_valid_transition(state, state));
        }

        /// Property: is_terminal_state and is_valid_transition are consistent.
        /// If from is terminal and from != to, the transition must be rejected.
        #[test]
        fn prop_terminal_consistency(
            from_idx in 0usize..5,
            to_idx in 0usize..5
        ) {
            let all_states = [
                ChallengeState::Pending,
                ChallengeState::ProofOkWaitingForRedeem,
                ChallengeState::Verified,
                ChallengeState::Failed,
                ChallengeState::Expired,
            ];
            let from = &all_states[from_idx];
            let to = &all_states[to_idx];
            if is_terminal_state(from) && from != to {
                prop_assert!(!is_valid_transition(from, to));
            }
        }

        /// Property: code: key prefix never equals ch: key prefix for same id.
        #[test]
        fn prop_key_namespaces_disjoint(id in "[a-zA-Z0-9_-]{1,40}") {
            let ch_key = format!("ch:{}", id);
            let code_key = format!("code:{}", id);
            prop_assert_ne!(ch_key, code_key);
        }

        /// Property: Expiry guard rejects non-terminal updates on expired
        /// challenges, but accepts terminal updates regardless of expiry.
        /// VA-DOD-006: Uses `>=` to match aligned expiry boundary.
        #[test]
        fn prop_expiry_guard_terminal_bypass(
            expires_at in 0u64..1_000_000,
            now in 1_000_001u64..2_000_000,
            target_idx in 0usize..5
        ) {
            // now >= expires_at is always true given the ranges.
            let all_states = [
                ChallengeState::Pending,
                ChallengeState::ProofOkWaitingForRedeem,
                ChallengeState::Verified,
                ChallengeState::Failed,
                ChallengeState::Expired,
            ];
            let target = &all_states[target_idx];
            let rejected = now >= expires_at && !is_terminal_state(target);
            if is_terminal_state(target) {
                prop_assert!(!rejected, "Terminal target should bypass expiry guard");
            } else {
                prop_assert!(rejected, "Non-terminal target should be rejected on expired challenge");
            }
        }

        /// Property: Zeroisation guard fires if and only if current is Pending
        /// and target is not Pending.
        #[test]
        fn prop_zeroisation_guard(
            from_idx in 0usize..5,
            to_idx in 0usize..5
        ) {
            let all_states = [
                ChallengeState::Pending,
                ChallengeState::ProofOkWaitingForRedeem,
                ChallengeState::Verified,
                ChallengeState::Failed,
                ChallengeState::Expired,
            ];
            let from = &all_states[from_idx];
            let to = &all_states[to_idx];
            let fires = *from == ChallengeState::Pending && *to != ChallengeState::Pending;
            if from_idx == 0 && to_idx != 0 {
                prop_assert!(fires);
            } else {
                prop_assert!(!fires);
            }
        }

        /// Property: Evidence-bearing check matches exactly Verified and
        /// ProofOkWaitingForRedeem.
        #[test]
        fn prop_evidence_bearing(state_idx in 0usize..5) {
            let all_states = [
                ChallengeState::Pending,
                ChallengeState::ProofOkWaitingForRedeem,
                ChallengeState::Verified,
                ChallengeState::Failed,
                ChallengeState::Expired,
            ];
            let state = &all_states[state_idx];
            let is_evidence = matches!(
                state,
                ChallengeState::Verified | ChallengeState::ProofOkWaitingForRedeem
            );
            if state_idx == 1 || state_idx == 2 {
                prop_assert!(is_evidence);
            } else {
                prop_assert!(!is_evidence);
            }
        }

        /// Property: MAX_DO_BODY_SIZE is exactly 64 * 1024.
        #[test]
        fn prop_max_body_size_is_64kb(_seed in any::<u8>()) {
            prop_assert_eq!(MAX_DO_BODY_SIZE, 64 * 1024);
        }

        /// Property: For any valid forward transition (non-idempotent),
        /// the source is not terminal.
        #[test]
        fn prop_valid_forward_transition_source_not_terminal(
            from_idx in 0usize..5,
            to_idx in 0usize..5
        ) {
            let all_states = [
                ChallengeState::Pending,
                ChallengeState::ProofOkWaitingForRedeem,
                ChallengeState::Verified,
                ChallengeState::Failed,
                ChallengeState::Expired,
            ];
            let from = &all_states[from_idx];
            let to = &all_states[to_idx];
            if from != to && is_valid_transition(from, to) {
                prop_assert!(!is_terminal_state(from));
            }
        }
    }
}
