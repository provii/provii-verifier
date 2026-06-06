// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Error types for hosted verification flows with HTTP status code mapping.
//!
//! Named `HostedApiError` to avoid collision with provii-verifier's top-level `ApiError`.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Hosted API error types with automatic HTTP status code mapping.
///
/// This is the provii-verifier error type, renamed to `HostedApiError` to
/// avoid collision with provii-verifier's existing `crate::error::ApiError`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "error", content = "details")]
pub enum HostedApiError {
    /// Invalid request format or missing required fields (400)
    InvalidRequest { message: String },

    /// Authentication failed - invalid public key or signature (401)
    Unauthorized { message: String },

    /// Valid credentials but insufficient permissions (403)
    Forbidden { message: String },

    /// Requested resource not found (404)
    NotFound { resource: String },

    /// HTTP method not allowed for this endpoint (405)
    MethodNotAllowed { allowed: Vec<String> },

    /// Request conflicts with current server state (409)
    Conflict { message: String },

    /// Session or resource has expired (410)
    Gone { message: String },

    /// Rate limit exceeded (429)
    RateLimitExceeded {
        retry_after: u64,
        limit: u32,
        window: u32,
    },

    /// Insufficient credits (402 Payment Required)
    InsufficientCredits { message: String },

    /// Internal server error (500)
    InternalError { message: String },

    /// Service temporarily unavailable (503)
    ServiceUnavailable { message: String },

    /// Gateway timeout when calling upstream services (504)
    GatewayTimeout { service: String },
}

impl HostedApiError {
    /// Get the HTTP status code for this error as a u16.
    pub fn status_code(&self) -> u16 {
        match self {
            HostedApiError::InvalidRequest { .. } => 400,
            HostedApiError::Unauthorized { .. } => 401,
            HostedApiError::Forbidden { .. } => 403,
            HostedApiError::NotFound { .. } => 404,
            HostedApiError::MethodNotAllowed { .. } => 405,
            HostedApiError::Conflict { .. } => 409,
            HostedApiError::Gone { .. } => 410,
            HostedApiError::RateLimitExceeded { .. } => 429,
            HostedApiError::InsufficientCredits { .. } => 402,
            HostedApiError::InternalError { .. } => 500,
            HostedApiError::ServiceUnavailable { .. } => 503,
            HostedApiError::GatewayTimeout { .. } => 504,
        }
    }

    /// Get a human-readable error message.
    pub fn message(&self) -> String {
        match self {
            HostedApiError::InvalidRequest { message } => message.clone(),
            HostedApiError::Unauthorized { message } => message.clone(),
            HostedApiError::Forbidden { message } => message.clone(),
            HostedApiError::NotFound { resource } => {
                format!("Resource not found: {}", resource)
            }
            HostedApiError::MethodNotAllowed { allowed } => {
                format!(
                    "Method not allowed. Allowed methods: {}",
                    allowed.join(", ")
                )
            }
            HostedApiError::Conflict { message } => message.clone(),
            HostedApiError::Gone { message } => message.clone(),
            HostedApiError::RateLimitExceeded {
                retry_after,
                limit,
                window,
            } => format!(
                "Rate limit exceeded: {} requests per {} seconds. Retry after {} seconds",
                limit, window, retry_after
            ),
            HostedApiError::InsufficientCredits { message } => message.clone(),
            HostedApiError::InternalError { message } => message.clone(),
            HostedApiError::ServiceUnavailable { message } => message.clone(),
            HostedApiError::GatewayTimeout { service } => {
                format!("Gateway timeout when calling {}", service)
            }
        }
    }

    /// Create a new InvalidRequest error.
    pub fn invalid_request(message: impl Into<String>) -> Self {
        HostedApiError::InvalidRequest {
            message: message.into(),
        }
    }

    /// Create a new Unauthorized error.
    pub fn unauthorized(message: impl Into<String>) -> Self {
        HostedApiError::Unauthorized {
            message: message.into(),
        }
    }

    /// Create a new Forbidden error.
    pub fn forbidden(message: impl Into<String>) -> Self {
        HostedApiError::Forbidden {
            message: message.into(),
        }
    }

    /// Create a new NotFound error.
    pub fn not_found(resource: impl Into<String>) -> Self {
        HostedApiError::NotFound {
            resource: resource.into(),
        }
    }

    /// Create a new Conflict error.
    pub fn conflict(message: impl Into<String>) -> Self {
        HostedApiError::Conflict {
            message: message.into(),
        }
    }

    /// Create a new Gone error.
    pub fn gone(message: impl Into<String>) -> Self {
        HostedApiError::Gone {
            message: message.into(),
        }
    }

    /// Create a new InternalError.
    pub fn internal(message: impl Into<String>) -> Self {
        HostedApiError::InternalError {
            message: message.into(),
        }
    }

    /// Create a new ServiceUnavailable error.
    pub fn service_unavailable(message: impl Into<String>) -> Self {
        HostedApiError::ServiceUnavailable {
            message: message.into(),
        }
    }

    /// Create a new GatewayTimeout error.
    pub fn gateway_timeout(service: impl Into<String>) -> Self {
        HostedApiError::GatewayTimeout {
            service: service.into(),
        }
    }

    /// Create a new RateLimitExceeded error.
    pub fn rate_limit_exceeded(retry_after: u64, limit: u32, window: u32) -> Self {
        HostedApiError::RateLimitExceeded {
            retry_after,
            limit,
            window,
        }
    }

    /// Create a new InsufficientCredits error.
    pub fn insufficient_credits(message: impl Into<String>) -> Self {
        HostedApiError::InsufficientCredits {
            message: message.into(),
        }
    }
}

impl fmt::Display for HostedApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for HostedApiError {}

impl From<worker::Error> for HostedApiError {
    fn from(err: worker::Error) -> Self {
        HostedApiError::internal(format!("Worker error: {}", err))
    }
}

/// Standard error response format for hosted routes.
///
/// SECURITY: Error responses include a request_id for correlation but
/// the inner HostedApiError is sanitised in production to prevent information disclosure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedErrorResponse {
    /// Error type and details
    #[serde(flatten)]
    pub error: HostedApiError,

    /// Request ID for tracing
    pub request_id: String,

    /// Timestamp when error occurred (Unix seconds)
    pub timestamp: u64,
}

impl HostedErrorResponse {
    /// Create a new error response with request ID and timestamp.
    pub fn new(error: HostedApiError, request_id: String) -> Self {
        Self {
            error,
            request_id,
            timestamp: u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0),
        }
    }

    /// Get the HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        self.error.status_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_request_status_code() {
        let err = HostedApiError::invalid_request("Bad request");
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn test_unauthorized_status_code() {
        let err = HostedApiError::unauthorized("Invalid credentials");
        assert_eq!(err.status_code(), 401);
    }

    #[test]
    fn test_forbidden_status_code() {
        let err = HostedApiError::forbidden("Access denied");
        assert_eq!(err.status_code(), 403);
    }

    #[test]
    fn test_not_found_status_code() {
        let err = HostedApiError::not_found("session-123");
        assert_eq!(err.status_code(), 404);
    }

    #[test]
    fn test_rate_limit_status_code() {
        let err = HostedApiError::RateLimitExceeded {
            retry_after: 60,
            limit: 100,
            window: 60,
        };
        assert_eq!(err.status_code(), 429);
    }

    #[test]
    fn test_error_message() {
        let err = HostedApiError::invalid_request("Missing field: origin");
        assert_eq!(err.message(), "Missing field: origin");
    }

    #[test]
    fn test_not_found_message() {
        let err = HostedApiError::not_found("session-abc");
        assert_eq!(err.message(), "Resource not found: session-abc");
    }

    #[test]
    fn test_rate_limit_message() {
        let err = HostedApiError::RateLimitExceeded {
            retry_after: 30,
            limit: 50,
            window: 60,
        };
        assert!(err.message().contains("50 requests"));
        assert!(err.message().contains("60 seconds"));
        assert!(err.message().contains("30 seconds"));
    }

    #[test]
    fn test_error_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::invalid_request("Test error");
        let json = serde_json::to_string(&err)?;
        assert!(json.contains("InvalidRequest"));
        assert!(json.contains("Test error"));
        Ok(())
    }

    #[test]
    fn test_error_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"error":"InvalidRequest","details":{"message":"Test"}}"#;
        let err: HostedApiError = serde_json::from_str(json)?;
        assert_eq!(err, HostedApiError::invalid_request("Test"));
        Ok(())
    }

    #[test]
    fn test_error_response_creation() {
        let err = HostedApiError::unauthorized("Invalid key");
        let response = HostedErrorResponse::new(err.clone(), "req-123".to_string());
        assert_eq!(response.error, err);
        assert_eq!(response.request_id, "req-123");
        assert!(response.timestamp > 0);
    }

    #[test]
    fn test_error_response_status_code() {
        let err = HostedApiError::not_found("session");
        let response = HostedErrorResponse::new(err, "req-456".to_string());
        assert_eq!(response.status_code(), 404);
    }

    #[test]
    fn test_display_trait() {
        let err = HostedApiError::conflict("Session already exists");
        assert_eq!(format!("{}", err), "Session already exists");
    }

    #[test]
    fn test_method_not_allowed_message() {
        let err = HostedApiError::MethodNotAllowed {
            allowed: vec!["GET".to_string(), "POST".to_string()],
        };
        let msg = err.message();
        assert!(msg.contains("GET"));
        assert!(msg.contains("POST"));
    }

    // ── status_code() exhaustive coverage ──────────────────────────────

    #[test]
    fn test_conflict_status_code() {
        let err = HostedApiError::conflict("conflict");
        assert_eq!(err.status_code(), 409);
    }

    #[test]
    fn test_gone_status_code() {
        let err = HostedApiError::gone("expired");
        assert_eq!(err.status_code(), 410);
    }

    #[test]
    fn test_method_not_allowed_status_code() {
        let err = HostedApiError::MethodNotAllowed {
            allowed: vec!["GET".to_string()],
        };
        assert_eq!(err.status_code(), 405);
    }

    #[test]
    fn test_insufficient_credits_status_code() {
        let err = HostedApiError::insufficient_credits("No credits");
        assert_eq!(err.status_code(), 402);
    }

    #[test]
    fn test_internal_error_status_code() {
        let err = HostedApiError::internal("DB failure");
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn test_service_unavailable_status_code() {
        let err = HostedApiError::service_unavailable("Maintenance");
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn test_gateway_timeout_status_code() {
        let err = HostedApiError::gateway_timeout("upstream");
        assert_eq!(err.status_code(), 504);
    }

    // ── message() coverage for all variants ────────────────────────────

    #[test]
    fn test_unauthorized_message() {
        let err = HostedApiError::unauthorized("Bad token");
        assert_eq!(err.message(), "Bad token");
    }

    #[test]
    fn test_forbidden_message() {
        let err = HostedApiError::forbidden("No access");
        assert_eq!(err.message(), "No access");
    }

    #[test]
    fn test_conflict_message() {
        let err = HostedApiError::conflict("Already exists");
        assert_eq!(err.message(), "Already exists");
    }

    #[test]
    fn test_gone_message() {
        let err = HostedApiError::gone("Session expired");
        assert_eq!(err.message(), "Session expired");
    }

    #[test]
    fn test_insufficient_credits_message() {
        let err = HostedApiError::insufficient_credits("Balance zero");
        assert_eq!(err.message(), "Balance zero");
    }

    #[test]
    fn test_internal_error_message() {
        let err = HostedApiError::internal("Crypto failure");
        assert_eq!(err.message(), "Crypto failure");
    }

    #[test]
    fn test_service_unavailable_message() {
        let err = HostedApiError::service_unavailable("Down for maintenance");
        assert_eq!(err.message(), "Down for maintenance");
    }

    #[test]
    fn test_gateway_timeout_message() {
        let err = HostedApiError::gateway_timeout("provii-verifier");
        assert_eq!(
            err.message(),
            "Gateway timeout when calling provii-verifier"
        );
    }

    #[test]
    fn test_method_not_allowed_message_single_method() {
        let err = HostedApiError::MethodNotAllowed {
            allowed: vec!["DELETE".to_string()],
        };
        let msg = err.message();
        assert!(msg.contains("DELETE"));
        assert!(msg.contains("Method not allowed"));
    }

    // ── Display trait for all variants ──────────────────────────────────

    #[test]
    fn test_display_invalid_request() {
        let err = HostedApiError::invalid_request("Bad input");
        assert_eq!(format!("{}", err), "Bad input");
    }

    #[test]
    fn test_display_not_found() {
        let err = HostedApiError::not_found("widget-xyz");
        assert_eq!(format!("{}", err), "Resource not found: widget-xyz");
    }

    #[test]
    fn test_display_rate_limit() {
        let err = HostedApiError::rate_limit_exceeded(60, 100, 60);
        let display = format!("{}", err);
        assert!(display.contains("100 requests"));
        assert!(display.contains("60 seconds"));
    }

    #[test]
    fn test_display_gateway_timeout() {
        let err = HostedApiError::gateway_timeout("provii-issuer");
        assert_eq!(
            format!("{}", err),
            "Gateway timeout when calling provii-issuer"
        );
    }

    // ── std::error::Error trait ────────────────────────────────────────

    #[test]
    fn test_error_trait_source_is_none() {
        let err = HostedApiError::internal("test");
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    // ── HostedApiError serde roundtrip ─────────────────────────────────

    #[test]
    fn test_unauthorized_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::unauthorized("Invalid key");
        let json = serde_json::to_string(&err)?;
        let decoded: HostedApiError = serde_json::from_str(&json)?;
        assert_eq!(decoded, err);
        Ok(())
    }

    #[test]
    fn test_forbidden_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::forbidden("Access denied");
        let json = serde_json::to_string(&err)?;
        let decoded: HostedApiError = serde_json::from_str(&json)?;
        assert_eq!(decoded, err);
        Ok(())
    }

    #[test]
    fn test_not_found_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::not_found("session-123");
        let json = serde_json::to_string(&err)?;
        let decoded: HostedApiError = serde_json::from_str(&json)?;
        assert_eq!(decoded, err);
        Ok(())
    }

    #[test]
    fn test_conflict_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::conflict("Already redeemed");
        let json = serde_json::to_string(&err)?;
        let decoded: HostedApiError = serde_json::from_str(&json)?;
        assert_eq!(decoded, err);
        Ok(())
    }

    #[test]
    fn test_gone_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::gone("Expired");
        let json = serde_json::to_string(&err)?;
        let decoded: HostedApiError = serde_json::from_str(&json)?;
        assert_eq!(decoded, err);
        Ok(())
    }

    #[test]
    fn test_rate_limit_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::rate_limit_exceeded(30, 50, 60);
        let json = serde_json::to_string(&err)?;
        let decoded: HostedApiError = serde_json::from_str(&json)?;
        assert_eq!(decoded, err);
        Ok(())
    }

    #[test]
    fn test_insufficient_credits_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::insufficient_credits("No credits");
        let json = serde_json::to_string(&err)?;
        let decoded: HostedApiError = serde_json::from_str(&json)?;
        assert_eq!(decoded, err);
        Ok(())
    }

    #[test]
    fn test_internal_error_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::internal("DB crash");
        let json = serde_json::to_string(&err)?;
        let decoded: HostedApiError = serde_json::from_str(&json)?;
        assert_eq!(decoded, err);
        Ok(())
    }

    #[test]
    fn test_service_unavailable_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::service_unavailable("Maintenance");
        let json = serde_json::to_string(&err)?;
        let decoded: HostedApiError = serde_json::from_str(&json)?;
        assert_eq!(decoded, err);
        Ok(())
    }

    #[test]
    fn test_gateway_timeout_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::gateway_timeout("upstream");
        let json = serde_json::to_string(&err)?;
        let decoded: HostedApiError = serde_json::from_str(&json)?;
        assert_eq!(decoded, err);
        Ok(())
    }

    #[test]
    fn test_method_not_allowed_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::MethodNotAllowed {
            allowed: vec!["GET".to_string(), "POST".to_string()],
        };
        let json = serde_json::to_string(&err)?;
        let decoded: HostedApiError = serde_json::from_str(&json)?;
        assert_eq!(decoded, err);
        Ok(())
    }

    // ── HostedApiError Clone + PartialEq ───────────────────────────────

    #[test]
    fn test_error_clone() {
        let err = HostedApiError::invalid_request("test");
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_error_inequality() {
        let err1 = HostedApiError::invalid_request("a");
        let err2 = HostedApiError::invalid_request("b");
        assert_ne!(err1, err2);
    }

    #[test]
    fn test_error_variant_inequality() {
        let err1 = HostedApiError::invalid_request("test");
        let err2 = HostedApiError::unauthorized("test");
        assert_ne!(err1, err2);
    }

    // ── HostedErrorResponse ────────────────────────────────────────────

    #[test]
    fn test_error_response_preserves_request_id() {
        let err = HostedApiError::internal("failure");
        let resp = HostedErrorResponse::new(err, "req-preserve".to_string());
        assert_eq!(resp.request_id, "req-preserve");
    }

    #[test]
    fn test_error_response_has_valid_timestamp() {
        let err = HostedApiError::forbidden("denied");
        let resp = HostedErrorResponse::new(err, "req-ts".to_string());
        assert!(resp.timestamp > 0, "timestamp should be > 0");
    }

    #[test]
    fn test_error_response_status_code_delegates() {
        let err = HostedApiError::rate_limit_exceeded(10, 20, 30);
        let resp = HostedErrorResponse::new(err, "req-sc".to_string());
        assert_eq!(resp.status_code(), 429);
    }

    #[test]
    fn test_error_response_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::unauthorized("bad key");
        let resp = HostedErrorResponse::new(err, "req-ser".to_string());
        let json = serde_json::to_string(&resp)?;
        assert!(json.contains("req-ser"));
        assert!(json.contains("Unauthorized"));
        assert!(json.contains("bad key"));
        assert!(json.contains("timestamp"));
        Ok(())
    }

    #[test]
    fn test_error_response_deny_unknown_fields() {
        let json = r#"{"error":"InvalidRequest","details":{"message":"t"},"request_id":"r","timestamp":0,"extra":"bad"}"#;
        let result = serde_json::from_str::<HostedErrorResponse>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── Constructor helpers coverage ────────────────────────────────────

    #[test]
    fn test_constructor_rate_limit_exceeded() {
        let err = HostedApiError::rate_limit_exceeded(10, 100, 60);
        assert_eq!(err.status_code(), 429);
        let msg = err.message();
        assert!(msg.contains("100 requests"));
        assert!(msg.contains("60 seconds"));
        assert!(msg.contains("10 seconds"));
    }

    #[test]
    fn test_constructor_method_not_allowed_empty() {
        let err = HostedApiError::MethodNotAllowed { allowed: vec![] };
        let msg = err.message();
        assert!(msg.contains("Method not allowed"));
    }

    // ── Debug trait ────────────────────────────────────────────────────

    #[test]
    fn test_error_debug_output() {
        let err = HostedApiError::internal("debug test");
        let debug = format!("{:?}", err);
        assert!(debug.contains("InternalError"));
        assert!(debug.contains("debug test"));
    }

    #[test]
    fn test_error_response_debug_output() {
        let err = HostedApiError::not_found("session-dbg");
        let resp = HostedErrorResponse::new(err, "req-dbg".to_string());
        let debug = format!("{:?}", resp);
        assert!(debug.contains("req-dbg"));
        assert!(debug.contains("session-dbg"));
    }

    #[test]
    fn test_rate_limit_exceeded_constructor_fields() {
        let err = HostedApiError::rate_limit_exceeded(45, 200, 120);
        match err {
            HostedApiError::RateLimitExceeded {
                retry_after,
                limit,
                window,
            } => {
                assert_eq!(retry_after, 45);
                assert_eq!(limit, 200);
                assert_eq!(window, 120);
            }
            _ => panic!("expected RateLimitExceeded variant"), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    #[test]
    fn test_gateway_timeout_serialises_service_field() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::gateway_timeout("provii-issuer");
        let json = serde_json::to_string(&err)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["details"]["service"], "provii-issuer");
        assert!(parsed["details"].get("message").is_none());
        Ok(())
    }

    #[test]
    fn test_display_service_unavailable() {
        let err = HostedApiError::service_unavailable("Planned outage");
        assert_eq!(format!("{}", err), "Planned outage");
    }

    #[test]
    fn test_display_insufficient_credits() {
        let err = HostedApiError::insufficient_credits("Zero balance");
        assert_eq!(format!("{}", err), "Zero balance");
    }

    #[test]
    fn test_display_method_not_allowed() {
        let err = HostedApiError::MethodNotAllowed {
            allowed: vec!["PUT".to_string(), "PATCH".to_string()],
        };
        let display = format!("{}", err);
        assert!(display.contains("PUT"));
        assert!(display.contains("PATCH"));
        assert!(display.contains("Method not allowed"));
    }

    #[test]
    fn test_error_response_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let err = HostedApiError::gone("Session expired");
        let resp = HostedErrorResponse::new(err, "req-rt".to_string());
        let json = serde_json::to_string(&resp)?;
        let decoded: HostedErrorResponse = serde_json::from_str(&json)?;
        assert_eq!(decoded.error, HostedApiError::gone("Session expired"));
        assert_eq!(decoded.request_id, "req-rt");
        assert_eq!(decoded.timestamp, resp.timestamp);
        Ok(())
    }

    #[test]
    fn test_method_not_allowed_message_empty_vec() {
        let err = HostedApiError::MethodNotAllowed { allowed: vec![] };
        assert_eq!(err.message(), "Method not allowed. Allowed methods: ");
    }
}
