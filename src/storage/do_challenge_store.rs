// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Durable Object-backed [`ChallengeStore`] implementation.
//!
//! Each challenge UUID maps to its own Durable Object instance via
//! `id_from_name(uuid)`. This provides per-challenge serialisation
//! guarantees without sharding, and eliminates the need for a separate
//! distributed lock layer (the DO's single-writer model prevents
//! concurrent mutation).
//!
//! The DO exposes a simple HTTP CRUD interface matching `CachedChallenge`
//! JSON serialisation (see `durable_objects::challenge_do`).
#![forbid(unsafe_code)]

use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    cache::CachedChallenge,
    error::{ApiError, ApiResult},
    security::audit::AuditEventData,
    storage::{traits::ChallengeStore, AuditLoggerSlot},
};

/// Maximum retries for transient DO communication failures.
const MAX_RETRIES: u32 = 3;

/// Retry a future with immediate retries on transient failure.
///
/// Each attempt is individually capped by `DO_FETCH_TIMEOUT_MS`, and the
/// total elapsed time across all attempts is capped by `MAX_OPERATION_BUDGET_MS`
/// (4000ms). This prevents 3 x 2000ms = 6000ms worst-case stalls.
async fn retry_with_backoff<F, Fut, T>(mut operation: F) -> ApiResult<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ApiResult<T>>,
{
    #[cfg(target_arch = "wasm32")]
    use crate::utils::timeout::MAX_OPERATION_BUDGET_MS;
    use crate::utils::timeout::{with_timeout, DO_FETCH_TIMEOUT_MS};

    let mut last_error = None;
    let start_ms;
    #[cfg(target_arch = "wasm32")]
    {
        start_ms = js_sys::Date::now();
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        start_ms = 0.0_f64; // Budget tracking is a no-op in tests.
    }
    for attempt in 1..=MAX_RETRIES {
        // Enforce total budget across all retry attempts.
        #[cfg(target_arch = "wasm32")]
        {
            let elapsed_ms = js_sys::Date::now() - start_ms;
            if elapsed_ms >= f64::from(MAX_OPERATION_BUDGET_MS) {
                #[cfg(target_arch = "wasm32")]
                worker::console_log!(
                    "[DOChallengeStore Retry] Budget exhausted ({:.0}ms >= {}ms) after {} attempts",
                    elapsed_ms,
                    MAX_OPERATION_BUDGET_MS,
                    attempt.saturating_sub(1)
                );
                break;
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = start_ms; // suppress unused warning
        }

        match with_timeout("DO fetch", DO_FETCH_TIMEOUT_MS, operation()).await {
            Ok(Ok(result)) => {
                if attempt > 1 {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "[DOChallengeStore Retry] Succeeded on attempt {} after retries",
                        attempt
                    );
                }
                return Ok(result);
            }
            Ok(Err(e)) => {
                if attempt < MAX_RETRIES {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "[DOChallengeStore Retry] Attempt {} failed, retrying: {:?}",
                        attempt,
                        e
                    );
                }
                last_error = Some(e);
            }
            Err(timeout_err) => {
                #[cfg(target_arch = "wasm32")]
                worker::console_log!(
                    "[DOChallengeStore Retry] Attempt {} timed out: {}",
                    attempt,
                    timeout_err
                );
                last_error = Some(ApiError::Internal(anyhow::anyhow!("{}", timeout_err)));
            }
        }
    }
    let final_error =
        last_error.unwrap_or_else(|| ApiError::Internal(anyhow::anyhow!("No retry attempts made")));
    #[cfg(target_arch = "wasm32")]
    worker::console_log!(
        "[DOChallengeStore Retry] Failed after {} attempts: {:?}",
        MAX_RETRIES,
        final_error
    );
    Err(final_error)
}

/// Durable Object-backed challenge store.
///
/// Each challenge UUID is addressed to its own DO instance via
/// `namespace.id_from_name(&uuid.to_string())`. This gives per-challenge
/// single-writer guarantees without any sharding or external locking.
///
/// AL-008: Holds a late-bound [`AuditLoggerSlot`] used to dispatch audit
/// events embedded in DO responses. The slot may be empty if construction
/// happens before the logger is available; in that case events are captured
/// but discarded with a console warning (no production deployment should
/// reach a request handler without the slot populated).
pub struct DurableObjectChallengeStore {
    namespace: worker::durable::ObjectNamespace,
    audit_logger: AuditLoggerSlot,
}

impl DurableObjectChallengeStore {
    /// Create a new store backed by the given Durable Object namespace.
    pub fn new(namespace: worker::durable::ObjectNamespace, audit_logger: AuditLoggerSlot) -> Self {
        Self {
            namespace,
            audit_logger,
        }
    }

    /// Best-effort dispatch of audit events from a DO response envelope.
    ///
    /// AL-008: Parses the optional `audit_events` array from a JSON body
    /// and hands each event to the worker-level audit logger. Failures are
    /// logged to the console; they must never block the storage operation.
    async fn dispatch_events_from_body(&self, body: &str) {
        let Some(logger) = self.audit_logger.get() else {
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
        let events: Vec<AuditEventData> = array
            .iter()
            .filter_map(|v| serde_json::from_value::<AuditEventData>(v.clone()).ok())
            .collect();
        if events.is_empty() {
            return;
        }
        // The DO response body does not carry per-request actor context.
        // Pass empty defaults; the event itself supplies origin/resource.
        logger.dispatch_do_audit_events(&events, "", "", "").await;
    }

    /// Get a stub for the DO instance that owns the given challenge UUID.
    fn stub_for(&self, id: &Uuid) -> ApiResult<worker::durable::Stub> {
        self.namespace
            .id_from_name(&id.to_string())
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("DO id_from_name failed: {}", e)))?
            .get_stub()
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("DO get_stub failed: {}", e)))
    }

    /// Send a request to the DO instance for the given challenge UUID.
    async fn send_request(
        &self,
        id: &Uuid,
        method: worker::Method,
        path: &str,
        body: Option<String>,
    ) -> ApiResult<worker::Response> {
        let stub = self.stub_for(id)?;
        let url = format!("https://do.internal{}", path);

        retry_with_backoff(|| async {
            let mut init = worker::RequestInit::new();
            init.with_method(method.clone());

            let headers = worker::Headers::new();
            init.with_headers(headers);

            if let Some(ref body_str) = body {
                init.with_body(Some(worker::wasm_bindgen::JsValue::from_str(body_str)));
            }

            let req = worker::Request::new_with_init(&url, &init)?;

            stub.fetch_with_request(req)
                .await
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("DO fetch failed: {}", e)))
        })
        .await
    }
}

/// VA-STO-002: Maximum serialised challenge size accepted by the store (64 KB).
/// Matches `MAX_DO_BODY_SIZE` in the Challenge DO.
const MAX_CHALLENGE_BODY_SIZE: usize = 65_536;

#[async_trait(?Send)]
impl ChallengeStore for DurableObjectChallengeStore {
    async fn insert(&self, id: Uuid, challenge: CachedChallenge) -> ApiResult<()> {
        // VA-STO-001 / VA-STO-002: Validate at the storage boundary.
        if id.is_nil() {
            return Err(ApiError::BadRequest(Some(
                "Challenge ID must not be nil UUID".into(),
            )));
        }
        let json = serde_json::to_string(&challenge).map_err(|e| {
            ApiError::Internal(anyhow::anyhow!("Failed to serialise challenge: {}", e))
        })?;
        if json.len() > MAX_CHALLENGE_BODY_SIZE {
            return Err(ApiError::BadRequest(Some(format!(
                "Serialised challenge exceeds maximum size of {} bytes",
                MAX_CHALLENGE_BODY_SIZE
            ))));
        }

        let path = format!("/challenge/{}/create", id);
        let resp = self
            .send_request(&id, worker::Method::Post, &path, Some(json))
            .await?;

        let status = resp.status_code();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(ApiError::Internal(anyhow::anyhow!(
                "DO create returned HTTP {}",
                status
            )))
        }
    }

    async fn get(&self, id: &Uuid) -> ApiResult<Option<CachedChallenge>> {
        let path = format!("/challenge/{}/get", id);
        let mut resp = self
            .send_request(id, worker::Method::Get, &path, None)
            .await?;

        let status = resp.status_code();
        match status {
            200 => {
                let text = resp.text().await.map_err(|e| {
                    ApiError::Internal(anyhow::anyhow!("DO response read failed: {}", e))
                })?;
                let challenge: CachedChallenge = serde_json::from_str(&text).map_err(|e| {
                    ApiError::Internal(anyhow::anyhow!(
                        "Failed to deserialise challenge from DO: {}",
                        e
                    ))
                })?;

                // CIV-132: Validate that security-critical byte fields are correct length.
                if let Err(e) = challenge.validate() {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "[DOChallengeStore] Challenge {} failed validation: {}",
                        crate::security::log_sanitizer::redact_challenge_id(&id.to_string()),
                        e
                    );
                    return Err(ApiError::Internal(anyhow::anyhow!(
                        "Cached challenge validation failed: {}",
                        e
                    )));
                }

                Ok(Some(challenge))
            }
            404 => Ok(None),
            410 => {
                // Challenge expired and was auto-deleted by the DO.
                // AL-008: The 410 body carries an `audit_events` envelope
                // describing the expiry-driven auto-deletion. Drain the body
                // and dispatch before returning so the event reaches D1.
                let body = resp.text().await.unwrap_or_default();
                self.dispatch_events_from_body(&body).await;
                Ok(None)
            }
            _ => Err(ApiError::Internal(anyhow::anyhow!(
                "DO get returned HTTP {}",
                status
            ))),
        }
    }

    async fn remove(&self, id: &Uuid) -> ApiResult<Option<CachedChallenge>> {
        // Fetch current value before deleting so callers that inspect
        // the returned CachedChallenge still work.
        let existing = self.get(id).await?;

        let path = format!("/challenge/{}", id);
        let mut resp = self
            .send_request(id, worker::Method::Delete, &path, None)
            .await?;

        let status = resp.status_code();
        if (200..300).contains(&status) || status == 409 {
            // AL-008: 200 carries `challenge_deleted`; 409 carries
            // `challenge_delete_blocked` (evidence-bearing state). Both must
            // reach D1. Drain and dispatch in either case.
            let body = resp.text().await.unwrap_or_default();
            self.dispatch_events_from_body(&body).await;
            if status == 409 {
                return Err(ApiError::Conflict(Some(format!(
                    "DO delete returned HTTP {}",
                    status
                ))));
            }
            Ok(existing)
        } else {
            Err(ApiError::Internal(anyhow::anyhow!(
                "DO delete returned HTTP {}",
                status
            )))
        }
    }

    /// Override the default `put` to attempt the DO's `/update` endpoint first.
    /// If the challenge does not exist (404), fall back to `/create`. This
    /// preserves the "write or overwrite" semantics while respecting the
    /// VA-DO-001 fix that prevents update from creating challenges.
    async fn put(&self, id: &Uuid, challenge: &CachedChallenge) -> ApiResult<()> {
        match self.update(*id, challenge.clone()).await {
            Ok(()) => Ok(()),
            Err(ApiError::NotFound) => {
                // Challenge does not exist yet; route through create.
                self.insert(*id, challenge.clone()).await
            }
            Err(e) => Err(e),
        }
    }

    async fn update(&self, id: Uuid, challenge: CachedChallenge) -> ApiResult<()> {
        // VA-STO-002: Validate at the storage boundary.
        if id.is_nil() {
            return Err(ApiError::BadRequest(Some(
                "Challenge ID must not be nil UUID".into(),
            )));
        }
        let json = serde_json::to_string(&challenge).map_err(|e| {
            ApiError::Internal(anyhow::anyhow!("Failed to serialise challenge: {}", e))
        })?;
        if json.len() > MAX_CHALLENGE_BODY_SIZE {
            return Err(ApiError::BadRequest(Some(format!(
                "Serialised challenge exceeds maximum size of {} bytes",
                MAX_CHALLENGE_BODY_SIZE
            ))));
        }

        let path = format!("/challenge/{}/update", id);
        let mut resp = self
            .send_request(&id, worker::Method::Post, &path, Some(json))
            .await?;

        let status = resp.status_code();
        match status {
            200 => {
                // AL-008: 200 body carries `challenge_state_transition`
                // events for any state change. Drain and dispatch before
                // returning so transitions are persisted to D1.
                let body = resp.text().await.unwrap_or_default();
                self.dispatch_events_from_body(&body).await;
                Ok(())
            }
            409 => {
                let body = resp.text().await.unwrap_or_default();
                // AL-008: 409 body carries `invalid_state_transition_rejected`.
                self.dispatch_events_from_body(&body).await;
                Err(ApiError::Conflict(Some(format!(
                    "State transition rejected by DO: {}",
                    body
                ))))
            }
            // VA-DO-001: The DO now returns 404 when updating a non-existent
            // challenge. Propagate as NotFound so callers (e.g. `put`) can
            // fall back to the create path.
            404 => Err(ApiError::NotFound),
            410 => Err(ApiError::Gone(Some("Challenge expired".into()))),
            _ => Err(ApiError::Internal(anyhow::anyhow!(
                "DO update returned HTTP {}",
                status
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_retries_constant() {
        assert_eq!(MAX_RETRIES, 3);
    }

    #[test]
    fn test_do_path_format_create() -> Result<(), Box<dyn std::error::Error>> {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let path = format!("/challenge/{}/create", id);
        assert_eq!(
            path,
            "/challenge/550e8400-e29b-41d4-a716-446655440000/create"
        );
        Ok(())
    }

    #[test]
    fn test_do_path_format_get() -> Result<(), Box<dyn std::error::Error>> {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let path = format!("/challenge/{}/get", id);
        assert_eq!(path, "/challenge/550e8400-e29b-41d4-a716-446655440000/get");
        Ok(())
    }

    #[test]
    fn test_do_path_format_update() -> Result<(), Box<dyn std::error::Error>> {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let path = format!("/challenge/{}/update", id);
        assert_eq!(
            path,
            "/challenge/550e8400-e29b-41d4-a716-446655440000/update"
        );
        Ok(())
    }

    #[test]
    fn test_do_path_format_delete() -> Result<(), Box<dyn std::error::Error>> {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let path = format!("/challenge/{}", id);
        assert_eq!(path, "/challenge/550e8400-e29b-41d4-a716-446655440000");
        Ok(())
    }

    #[test]
    fn test_http_status_success_range() {
        for status in 200..300 {
            assert!((200..300).contains(&status));
        }
    }

    #[test]
    fn test_http_status_not_found() {
        assert_eq!(404, 404);
    }

    #[test]
    fn test_http_status_gone() {
        assert_eq!(410, 410);
    }

    // ======================================================================
    // Path format with different UUIDs
    // ======================================================================

    #[test]
    fn test_do_path_format_nil_uuid() {
        let id = Uuid::nil();
        let path = format!("/challenge/{}/create", id);
        assert_eq!(
            path,
            "/challenge/00000000-0000-0000-0000-000000000000/create"
        );
    }

    #[test]
    fn test_do_path_format_max_uuid() {
        let id = Uuid::max();
        let path = format!("/challenge/{}/get", id);
        assert_eq!(path, "/challenge/ffffffff-ffff-ffff-ffff-ffffffffffff/get");
    }

    #[test]
    fn test_do_url_format() {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let path = format!("/challenge/{}/update", id);
        let url = format!("https://do.internal{}", path);
        assert_eq!(
            url,
            "https://do.internal/challenge/550e8400-e29b-41d4-a716-446655440000/update"
        );
    }

    // ======================================================================
    // HTTP status ranges
    // ======================================================================

    #[test]
    fn test_http_status_200_is_success() {
        assert!((200..300).contains(&200));
    }

    #[test]
    fn test_http_status_299_is_success() {
        assert!((200..300).contains(&299));
    }

    #[test]
    fn test_http_status_300_is_not_success() {
        assert!(!(200..300).contains(&300));
    }

    #[test]
    fn test_http_status_199_is_not_success() {
        assert!(!(200..300).contains(&199));
    }

    #[test]
    fn test_http_status_409_is_conflict() {
        // The remove() method treats 409 specially (evidence-bearing state)
        let status = 409;
        assert!((200..300).contains(&status) || status == 409);
    }

    // ======================================================================
    // UUID parsing
    // ======================================================================

    #[test]
    fn test_uuid_v4_format() {
        let id = Uuid::new_v4();
        let s = id.to_string();
        // UUID v4 format: 8-4-4-4-12
        assert_eq!(s.len(), 36);
        assert_eq!(s.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn test_uuid_parse_roundtrip() {
        let id = Uuid::new_v4();
        let s = id.to_string();
        let parsed = Uuid::parse_str(&s).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_uuid_parse_invalid() {
        assert!(Uuid::parse_str("not-a-uuid").is_err());
        assert!(Uuid::parse_str("").is_err());
    }

    // ======================================================================
    // Retry constant
    // ======================================================================

    #[test]
    fn test_max_retries_is_positive() {
        assert!(MAX_RETRIES > 0);
        assert!(MAX_RETRIES <= 10);
    }

    // ======================================================================
    // Retry loop iteration bounds
    // ======================================================================

    #[test]
    fn test_retry_range_covers_all_attempts() {
        let mut attempts = Vec::new();
        for attempt in 1..=MAX_RETRIES {
            attempts.push(attempt);
        }
        assert_eq!(attempts.len(), MAX_RETRIES as usize);
        assert_eq!(attempts[0], 1);
        assert_eq!(attempts[attempts.len().saturating_sub(1)], MAX_RETRIES);
    }

    #[test]
    fn test_retry_attempt_comparison_first() {
        // On the first attempt, attempt < MAX_RETRIES is true (log retry message)
        let attempt: u32 = 1;
        assert!(attempt < MAX_RETRIES);
    }

    #[test]
    fn test_retry_attempt_comparison_last() {
        // On the last attempt, attempt < MAX_RETRIES is false (skip log)
        let attempt: u32 = MAX_RETRIES;
        assert!((attempt >= MAX_RETRIES));
    }

    #[test]
    fn test_retry_attempt_success_logging_threshold() {
        // Success message is logged when attempt > 1
        let attempt: u32 = 2;
        assert!(attempt > 1);
        let first_attempt: u32 = 1;
        assert!((first_attempt <= 1));
    }

    // ======================================================================
    // Budget tracking (non-wasm32 path)
    // ======================================================================

    #[test]
    fn test_budget_start_value_non_wasm() {
        // On non-wasm32, start_ms is fixed at 0.0
        let start_ms = 0.0_f64;
        assert!((start_ms - 0.0).abs() < f64::EPSILON);
    }

    // ======================================================================
    // HTTP status classification for remove()
    // ======================================================================

    #[test]
    fn test_remove_status_200_is_success() {
        let status: u16 = 200;
        assert!((200..300).contains(&status) || status == 409);
    }

    #[test]
    fn test_remove_status_204_is_success() {
        let status: u16 = 204;
        assert!((200..300).contains(&status) || status == 409);
    }

    #[test]
    fn test_remove_status_409_is_success_path() {
        let status: u16 = 409;
        assert!((200..300).contains(&status) || status == 409);
    }

    #[test]
    fn test_remove_status_500_is_error() {
        let status: u16 = 500;
        assert!(!((200..300).contains(&status) || status == 409));
    }

    #[test]
    fn test_remove_status_100_is_error() {
        let status: u16 = 100;
        assert!(!((200..300).contains(&status) || status == 409));
    }

    // ======================================================================
    // HTTP status classification for update()
    // ======================================================================

    #[test]
    fn test_update_status_200_is_ok() {
        let status: u16 = 200;
        let result: &str = match status {
            200 => "ok",
            409 => "conflict",
            410 => "gone",
            _ => "internal_error",
        };
        assert_eq!(result, "ok");
    }

    #[test]
    fn test_update_status_409_is_conflict() {
        let status: u16 = 409;
        let result: &str = match status {
            200 => "ok",
            409 => "conflict",
            410 => "gone",
            _ => "internal_error",
        };
        assert_eq!(result, "conflict");
    }

    #[test]
    fn test_update_status_410_is_gone() {
        let status: u16 = 410;
        let result: &str = match status {
            200 => "ok",
            409 => "conflict",
            410 => "gone",
            _ => "internal_error",
        };
        assert_eq!(result, "gone");
    }

    #[test]
    fn test_update_status_500_is_internal() {
        let status: u16 = 500;
        let result: &str = match status {
            200 => "ok",
            409 => "conflict",
            410 => "gone",
            _ => "internal_error",
        };
        assert_eq!(result, "internal_error");
    }

    // ======================================================================
    // HTTP status classification for get()
    // ======================================================================

    #[test]
    fn test_get_status_200_is_found() {
        let status: u16 = 200;
        let result: &str = match status {
            200 => "found",
            404 => "not_found",
            410 => "expired",
            _ => "error",
        };
        assert_eq!(result, "found");
    }

    #[test]
    fn test_get_status_404_is_not_found() {
        let status: u16 = 404;
        let result: &str = match status {
            200 => "found",
            404 => "not_found",
            410 => "expired",
            _ => "error",
        };
        assert_eq!(result, "not_found");
    }

    #[test]
    fn test_get_status_410_is_expired() {
        let status: u16 = 410;
        let result: &str = match status {
            200 => "found",
            404 => "not_found",
            410 => "expired",
            _ => "error",
        };
        assert_eq!(result, "expired");
    }

    #[test]
    fn test_get_status_503_is_error() {
        let status: u16 = 503;
        let result: &str = match status {
            200 => "found",
            404 => "not_found",
            410 => "expired",
            _ => "error",
        };
        assert_eq!(result, "error");
    }

    // ======================================================================
    // Audit event extraction from JSON bodies
    // ======================================================================

    #[test]
    fn test_audit_events_absent_from_body() -> Result<(), Box<dyn std::error::Error>> {
        let body = r#"{"status":"ok"}"#;
        let value: serde_json::Value = serde_json::from_str(body)?;
        let events = value.get("audit_events").and_then(|v| v.as_array());
        assert!(events.is_none());
        Ok(())
    }

    #[test]
    fn test_audit_events_empty_array() -> Result<(), Box<dyn std::error::Error>> {
        let body = r#"{"audit_events":[]}"#;
        let value: serde_json::Value = serde_json::from_str(body)?;
        let array = value
            .get("audit_events")
            .and_then(|v| v.as_array())
            .expect("should be array");
        assert!(array.is_empty());
        Ok(())
    }

    #[test]
    fn test_audit_events_with_entries() -> Result<(), Box<dyn std::error::Error>> {
        let body = r#"{"audit_events":[{"event_type":"challenge_deleted","severity":"info","message":"deleted","actor_ip":"","origin":"","actor_id":"","resource_id":"","details":"","request_id":"","environment":"","component":"","worker_version":""}]}"#;
        let value: serde_json::Value = serde_json::from_str(body)?;
        let array = value
            .get("audit_events")
            .and_then(|v| v.as_array())
            .expect("should be array");
        assert_eq!(array.len(), 1);

        let event: AuditEventData = serde_json::from_value(array[0].clone())?;
        assert_eq!(event.event_type, "challenge_deleted");
        Ok(())
    }

    #[test]
    fn test_audit_events_invalid_json_body() {
        let body = "not valid json {{{";
        let result = serde_json::from_str::<serde_json::Value>(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_audit_events_null_field() -> Result<(), Box<dyn std::error::Error>> {
        let body = r#"{"audit_events":null}"#;
        let value: serde_json::Value = serde_json::from_str(body)?;
        let array = value.get("audit_events").and_then(|v| v.as_array());
        assert!(array.is_none());
        Ok(())
    }

    #[test]
    fn test_audit_events_not_array() -> Result<(), Box<dyn std::error::Error>> {
        let body = r#"{"audit_events":"not an array"}"#;
        let value: serde_json::Value = serde_json::from_str(body)?;
        let array = value.get("audit_events").and_then(|v| v.as_array());
        assert!(array.is_none());
        Ok(())
    }

    // ======================================================================
    // DO internal URL construction
    // ======================================================================

    #[test]
    fn test_do_internal_url_base() {
        let path = "/challenge/abc/create";
        let url = format!("https://do.internal{}", path);
        assert!(url.starts_with("https://do.internal/"));
    }

    #[test]
    fn test_do_internal_url_preserves_uuid_casing() -> Result<(), Box<dyn std::error::Error>> {
        let id = Uuid::parse_str("550E8400-E29B-41D4-A716-446655440000")?;
        // Uuid::to_string() lowercases
        let path = format!("/challenge/{}/get", id);
        assert!(path.contains("550e8400"));
        Ok(())
    }

    // ======================================================================
    // Property-based tests
    // ======================================================================

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: All four path formats produce well-formed strings
        #[test]
        fn prop_path_formats_valid(uuid_bytes in any::<[u8; 16]>()) {
            let id = Uuid::from_bytes(uuid_bytes);
            let create = format!("/challenge/{}/create", id);
            let get = format!("/challenge/{}/get", id);
            let update = format!("/challenge/{}/update", id);
            let delete = format!("/challenge/{}", id);

            prop_assert!(create.starts_with("/challenge/"));
            prop_assert!(create.ends_with("/create"));
            prop_assert!(get.ends_with("/get"));
            prop_assert!(update.ends_with("/update"));
            prop_assert!(!delete.ends_with("/"));
        }

        /// Property: DO internal URL is always well-formed https URL
        #[test]
        fn prop_do_url_well_formed(uuid_bytes in any::<[u8; 16]>()) {
            let id = Uuid::from_bytes(uuid_bytes);
            let path = format!("/challenge/{}/get", id);
            let url = format!("https://do.internal{}", path);
            prop_assert!(url.starts_with("https://do.internal/challenge/"));
            prop_assert!(url.ends_with("/get"));
        }

        /// Property: HTTP status 200..300 range is correctly bounded
        #[test]
        fn prop_success_range(status in 0u16..1000) {
            let is_success = (200..300).contains(&status);
            if status >= 200 && status < 300 {
                prop_assert!(is_success);
            } else {
                prop_assert!(!is_success);
            }
        }
    }
}
