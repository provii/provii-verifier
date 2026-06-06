// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Error Code Enumeration
//!
//! This module provides standardised error codes for API consumers
//! to programmatically handle different error scenarios.

use crate::hosted::types::errors::HostedApiError;
use serde::{Deserialize, Serialize};

/// Standardised error codes for the hosted API
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    // 400 Bad Request Errors
    /// Invalid request format or parameters
    InvalidRequest,
    /// Invalid session ID format
    InvalidSessionId,
    /// Invalid code verifier format
    InvalidCodeVerifier,
    /// Invalid origin header
    InvalidOrigin,
    /// Invalid public key format
    InvalidPublicKey,
    /// Missing required field
    MissingRequiredField,
    /// Invalid field format
    InvalidFieldFormat,

    // 401 Unauthorized Errors
    /// Authentication required
    AuthenticationRequired,
    /// Invalid API key or signature
    InvalidCredentials,
    /// PKCE verification failed
    PkceVerificationFailed,
    /// Session token invalid
    InvalidSessionToken,
    /// Admin key invalid or expired
    InvalidAdminKey,

    // 403 Forbidden Errors
    /// Access denied
    AccessDenied,
    /// Insufficient permissions
    InsufficientPermissions,
    /// Session does not belong to user
    SessionOwnershipDenied,
    /// Origin mismatch
    OriginMismatch,
    /// Operation not allowed in current state
    OperationNotAllowed,
    /// Re-authentication required for sensitive operation
    ReauthRequired,

    // 404 Not Found Errors
    /// Session not found
    SessionNotFound,
    /// Resource not found
    ResourceNotFound,
    /// Public key not found
    PublicKeyNotFound,

    // 405 Method Not Allowed
    /// HTTP method not allowed
    MethodNotAllowed,

    // 409 Conflict Errors
    /// Session already redeemed
    SessionAlreadyRedeemed,
    /// Resource already exists
    ResourceAlreadyExists,
    /// Conflict with current state
    StateConflict,

    // 410 Gone Errors
    /// Session has expired
    SessionExpired,
    /// Session has been revoked
    SessionRevoked,
    /// Resource no longer available
    ResourceGone,

    // 402 Payment Required
    /// Insufficient credits (covers both low balance and fully exhausted)
    InsufficientCredits,

    // 429 Too Many Requests
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Too many redemption attempts
    TooManyRedemptionAttempts,
    /// Too many status checks
    TooManyStatusChecks,

    // 500 Internal Server Error
    /// Internal server error
    InternalServerError,
    /// Database error
    DatabaseError,
    /// Storage error
    StorageError,
    /// Encryption error
    EncryptionError,
    /// Token signing error
    TokenSigningError,

    // 503 Service Unavailable
    /// Service temporarily unavailable
    ServiceUnavailable,
    /// Circuit breaker open
    CircuitBreakerOpen,
    /// Service degraded
    ServiceDegraded,

    // 504 Gateway Timeout
    /// Gateway timeout
    GatewayTimeout,
    /// Verifier API timeout
    ProviiVerifierTimeout,
}

impl ErrorCode {
    /// Get human-readable description of the error code
    pub fn description(&self) -> &'static str {
        match self {
            ErrorCode::InvalidRequest => "The request format or parameters are invalid",
            ErrorCode::InvalidSessionId => "The session ID format is invalid",
            ErrorCode::InvalidCodeVerifier => "The PKCE code verifier is invalid",
            ErrorCode::InvalidOrigin => "The Origin header is invalid",
            ErrorCode::InvalidPublicKey => "The public key format is invalid",
            ErrorCode::MissingRequiredField => "A required field is missing",
            ErrorCode::InvalidFieldFormat => "A field has an invalid format",

            ErrorCode::AuthenticationRequired => "Authentication is required for this operation",
            ErrorCode::InvalidCredentials => "The provided credentials are invalid",
            ErrorCode::PkceVerificationFailed => "PKCE code verifier verification failed",
            ErrorCode::InvalidSessionToken => "The session token is invalid or expired",
            ErrorCode::InvalidAdminKey => "The admin key is invalid or expired",

            ErrorCode::AccessDenied => "Access to this resource is denied",
            ErrorCode::InsufficientPermissions => "You do not have sufficient permissions",
            ErrorCode::SessionOwnershipDenied => "You do not own this session",
            ErrorCode::OriginMismatch => "Request origin does not match session origin",
            ErrorCode::OperationNotAllowed => "This operation is not allowed in the current state",
            ErrorCode::ReauthRequired => {
                "Re-authentication is required for this sensitive operation"
            }

            ErrorCode::SessionNotFound => "The requested session was not found",
            ErrorCode::ResourceNotFound => "The requested resource was not found",
            ErrorCode::PublicKeyNotFound => "The public key was not found",

            ErrorCode::MethodNotAllowed => "The HTTP method is not allowed for this endpoint",

            ErrorCode::SessionAlreadyRedeemed => "This session has already been redeemed",
            ErrorCode::ResourceAlreadyExists => "The resource already exists",
            ErrorCode::StateConflict => "The request conflicts with the current state",

            ErrorCode::SessionExpired => "The session has expired",
            ErrorCode::SessionRevoked => "The session has been revoked",
            ErrorCode::ResourceGone => "The resource is no longer available",

            ErrorCode::InsufficientCredits => "Insufficient credits for this operation",

            ErrorCode::RateLimitExceeded => "Rate limit has been exceeded",
            ErrorCode::TooManyRedemptionAttempts => "Too many redemption attempts",
            ErrorCode::TooManyStatusChecks => "Too many status check requests",

            ErrorCode::InternalServerError => "An internal server error occurred",
            ErrorCode::DatabaseError => "A database error occurred",
            ErrorCode::StorageError => "A storage error occurred",
            ErrorCode::EncryptionError => "An encryption error occurred",
            ErrorCode::TokenSigningError => "A token signing error occurred",

            ErrorCode::ServiceUnavailable => "The service is temporarily unavailable",
            ErrorCode::CircuitBreakerOpen => "The circuit breaker is open",
            ErrorCode::ServiceDegraded => "The service is running in degraded mode",

            ErrorCode::GatewayTimeout => "A gateway timeout occurred",
            ErrorCode::ProviiVerifierTimeout => "The provii-verifier service timed out",
        }
    }

    /// Get the HTTP status code associated with this error code
    pub fn http_status(&self) -> u16 {
        match self {
            ErrorCode::InvalidRequest
            | ErrorCode::InvalidSessionId
            | ErrorCode::InvalidCodeVerifier
            | ErrorCode::InvalidOrigin
            | ErrorCode::InvalidPublicKey
            | ErrorCode::MissingRequiredField
            | ErrorCode::InvalidFieldFormat => 400,

            ErrorCode::AuthenticationRequired
            | ErrorCode::InvalidCredentials
            | ErrorCode::PkceVerificationFailed
            | ErrorCode::InvalidSessionToken
            | ErrorCode::InvalidAdminKey => 401,

            ErrorCode::AccessDenied
            | ErrorCode::InsufficientPermissions
            | ErrorCode::SessionOwnershipDenied
            | ErrorCode::OriginMismatch
            | ErrorCode::OperationNotAllowed
            | ErrorCode::ReauthRequired => 403,

            ErrorCode::SessionNotFound
            | ErrorCode::ResourceNotFound
            | ErrorCode::PublicKeyNotFound => 404,

            ErrorCode::MethodNotAllowed => 405,

            ErrorCode::SessionAlreadyRedeemed
            | ErrorCode::ResourceAlreadyExists
            | ErrorCode::StateConflict => 409,

            ErrorCode::SessionExpired | ErrorCode::SessionRevoked | ErrorCode::ResourceGone => 410,

            ErrorCode::InsufficientCredits => 402,

            ErrorCode::RateLimitExceeded
            | ErrorCode::TooManyRedemptionAttempts
            | ErrorCode::TooManyStatusChecks => 429,

            ErrorCode::InternalServerError
            | ErrorCode::DatabaseError
            | ErrorCode::StorageError
            | ErrorCode::EncryptionError
            | ErrorCode::TokenSigningError => 500,

            ErrorCode::ServiceUnavailable
            | ErrorCode::CircuitBreakerOpen
            | ErrorCode::ServiceDegraded => 503,

            ErrorCode::GatewayTimeout | ErrorCode::ProviiVerifierTimeout => 504,
        }
    }

    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::InvalidRequest => "INVALID_REQUEST",
            ErrorCode::InvalidSessionId => "INVALID_SESSION_ID",
            ErrorCode::InvalidCodeVerifier => "INVALID_CODE_VERIFIER",
            ErrorCode::InvalidOrigin => "INVALID_ORIGIN",
            ErrorCode::InvalidPublicKey => "INVALID_PUBLIC_KEY",
            ErrorCode::MissingRequiredField => "MISSING_REQUIRED_FIELD",
            ErrorCode::InvalidFieldFormat => "INVALID_FIELD_FORMAT",

            ErrorCode::AuthenticationRequired => "AUTHENTICATION_REQUIRED",
            ErrorCode::InvalidCredentials => "INVALID_CREDENTIALS",
            ErrorCode::PkceVerificationFailed => "PKCE_VERIFICATION_FAILED",
            ErrorCode::InvalidSessionToken => "INVALID_SESSION_TOKEN",
            ErrorCode::InvalidAdminKey => "INVALID_ADMIN_KEY",

            ErrorCode::AccessDenied => "ACCESS_DENIED",
            ErrorCode::InsufficientPermissions => "INSUFFICIENT_PERMISSIONS",
            ErrorCode::SessionOwnershipDenied => "SESSION_OWNERSHIP_DENIED",
            ErrorCode::OriginMismatch => "ORIGIN_MISMATCH",
            ErrorCode::OperationNotAllowed => "OPERATION_NOT_ALLOWED",
            ErrorCode::ReauthRequired => "REAUTH_REQUIRED",

            ErrorCode::SessionNotFound => "SESSION_NOT_FOUND",
            ErrorCode::ResourceNotFound => "RESOURCE_NOT_FOUND",
            ErrorCode::PublicKeyNotFound => "PUBLIC_KEY_NOT_FOUND",

            ErrorCode::MethodNotAllowed => "METHOD_NOT_ALLOWED",

            ErrorCode::SessionAlreadyRedeemed => "SESSION_ALREADY_REDEEMED",
            ErrorCode::ResourceAlreadyExists => "RESOURCE_ALREADY_EXISTS",
            ErrorCode::StateConflict => "STATE_CONFLICT",

            ErrorCode::SessionExpired => "SESSION_EXPIRED",
            ErrorCode::SessionRevoked => "SESSION_REVOKED",
            ErrorCode::ResourceGone => "RESOURCE_GONE",

            ErrorCode::InsufficientCredits => "INSUFFICIENT_CREDITS",

            ErrorCode::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            ErrorCode::TooManyRedemptionAttempts => "TOO_MANY_REDEMPTION_ATTEMPTS",
            ErrorCode::TooManyStatusChecks => "TOO_MANY_STATUS_CHECKS",

            ErrorCode::InternalServerError => "INTERNAL_SERVER_ERROR",
            ErrorCode::DatabaseError => "DATABASE_ERROR",
            ErrorCode::StorageError => "STORAGE_ERROR",
            ErrorCode::EncryptionError => "ENCRYPTION_ERROR",
            ErrorCode::TokenSigningError => "TOKEN_SIGNING_ERROR",

            ErrorCode::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            ErrorCode::CircuitBreakerOpen => "CIRCUIT_BREAKER_OPEN",
            ErrorCode::ServiceDegraded => "SERVICE_DEGRADED",

            ErrorCode::GatewayTimeout => "GATEWAY_TIMEOUT",
            ErrorCode::ProviiVerifierTimeout => "PROVII_VERIFIER_TIMEOUT",
        }
    }
}

/// SECURITY: Map a HostedApiError to an ErrorCode.
///
/// Internal errors (500, 503, 504) always map to a single generic code to
/// prevent subsystem architecture leakage via error code enumeration (EIL-021).
pub fn map_error_to_code(error: &HostedApiError) -> ErrorCode {
    match error {
        HostedApiError::InvalidRequest { message } => {
            // Try to infer more specific error code from message
            if message.contains("session") {
                ErrorCode::InvalidSessionId
            } else if message.contains("verifier") {
                ErrorCode::InvalidCodeVerifier
            } else if message.contains("origin") || message.contains("Origin") {
                ErrorCode::InvalidOrigin
            } else if message.contains("public key") || message.contains("public_key") {
                ErrorCode::InvalidPublicKey
            } else if message.contains("missing") || message.contains("required") {
                ErrorCode::MissingRequiredField
            } else {
                ErrorCode::InvalidRequest
            }
        }

        HostedApiError::Unauthorized { message } => {
            if message.contains("PKCE") || message.contains("verifier") {
                ErrorCode::PkceVerificationFailed
            } else if message.contains("admin") {
                ErrorCode::InvalidAdminKey
            } else if message.contains("token") {
                ErrorCode::InvalidSessionToken
            } else {
                ErrorCode::InvalidCredentials
            }
        }

        HostedApiError::Forbidden { message } => {
            if message.contains("Re-authentication") || message.contains("re-authenticate") {
                ErrorCode::ReauthRequired
            } else if message.contains("ownership") || message.contains("belong") {
                ErrorCode::SessionOwnershipDenied
            } else if message.contains("origin") {
                ErrorCode::OriginMismatch
            } else if message.contains("permission") {
                ErrorCode::InsufficientPermissions
            } else {
                ErrorCode::AccessDenied
            }
        }

        HostedApiError::NotFound { resource } => {
            if resource.contains("session") {
                ErrorCode::SessionNotFound
            } else if resource.contains("public_key") || resource.contains("key") {
                ErrorCode::PublicKeyNotFound
            } else {
                ErrorCode::ResourceNotFound
            }
        }

        HostedApiError::MethodNotAllowed { .. } => ErrorCode::MethodNotAllowed,

        HostedApiError::Conflict { message } => {
            if message.contains("redeemed") {
                ErrorCode::SessionAlreadyRedeemed
            } else if message.contains("exists") {
                ErrorCode::ResourceAlreadyExists
            } else {
                ErrorCode::StateConflict
            }
        }

        HostedApiError::Gone { message } => {
            if message.contains("expired") {
                ErrorCode::SessionExpired
            } else if message.contains("revoked") {
                ErrorCode::SessionRevoked
            } else {
                ErrorCode::ResourceGone
            }
        }

        HostedApiError::RateLimitExceeded { .. } => ErrorCode::RateLimitExceeded,

        HostedApiError::InsufficientCredits { .. } => ErrorCode::InsufficientCredits,

        // EIL-021: Internal error codes must NOT be derived from message content.
        // Exposing specific subsystem failure codes (DatabaseError, StorageError,
        // EncryptionError, etc.) helps attackers map the internal architecture.
        // All internal errors return a single generic code.
        HostedApiError::InternalError { .. } => ErrorCode::InternalServerError,

        // EIL-021: Same principle for service unavailable errors.
        HostedApiError::ServiceUnavailable { .. } => ErrorCode::ServiceUnavailable,

        // EIL-021: Same principle for gateway timeouts.
        HostedApiError::GatewayTimeout { .. } => ErrorCode::GatewayTimeout,
    }
}

/// Enhanced error response with error code
///
/// Canonical shape: `{"error":"...","code":"...","request_id":"..."}`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponseWithCode {
    /// Human-readable error message
    pub error: String,

    /// Error code
    pub code: ErrorCode,

    /// Request ID for tracing
    pub request_id: String,
}

impl ErrorResponseWithCode {
    /// Create a new error response with code
    pub fn from_hosted_api_error(error: HostedApiError, request_id: String) -> Self {
        let code = map_error_to_code(&error);
        let error_message = error.message();

        Self {
            error: error_message,
            code,
            request_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_description() {
        assert_eq!(
            ErrorCode::InvalidSessionId.description(),
            "The session ID format is invalid"
        );
        assert_eq!(
            ErrorCode::AccessDenied.description(),
            "Access to this resource is denied"
        );
    }

    #[test]
    fn test_error_code_http_status() {
        assert_eq!(ErrorCode::InvalidRequest.http_status(), 400);
        assert_eq!(ErrorCode::AuthenticationRequired.http_status(), 401);
        assert_eq!(ErrorCode::AccessDenied.http_status(), 403);
        assert_eq!(ErrorCode::SessionNotFound.http_status(), 404);
        assert_eq!(ErrorCode::RateLimitExceeded.http_status(), 429);
        assert_eq!(ErrorCode::InternalServerError.http_status(), 500);
    }

    #[test]
    fn test_error_code_as_str() {
        assert_eq!(ErrorCode::InvalidSessionId.as_str(), "INVALID_SESSION_ID");
        assert_eq!(ErrorCode::SessionExpired.as_str(), "SESSION_EXPIRED");
        assert_eq!(ErrorCode::RateLimitExceeded.as_str(), "RATE_LIMIT_EXCEEDED");
    }

    #[test]
    fn test_map_invalid_request_to_code() {
        let error = HostedApiError::invalid_request("Invalid session ID format");
        let code = map_error_to_code(&error);
        assert_eq!(code, ErrorCode::InvalidSessionId);

        let error2 = HostedApiError::invalid_request("Missing required field: name");
        let code2 = map_error_to_code(&error2);
        assert_eq!(code2, ErrorCode::MissingRequiredField);
    }

    #[test]
    fn test_map_unauthorized_to_code() {
        let error = HostedApiError::unauthorized("PKCE verification failed");
        let code = map_error_to_code(&error);
        assert_eq!(code, ErrorCode::PkceVerificationFailed);

        let error2 = HostedApiError::unauthorized("Invalid admin key");
        let code2 = map_error_to_code(&error2);
        assert_eq!(code2, ErrorCode::InvalidAdminKey);
    }

    #[test]
    fn test_map_forbidden_to_code() {
        let error = HostedApiError::forbidden("Session does not belong to user");
        let code = map_error_to_code(&error);
        assert_eq!(code, ErrorCode::SessionOwnershipDenied);

        let error2 = HostedApiError::forbidden("origin mismatch");
        let code2 = map_error_to_code(&error2);
        assert_eq!(code2, ErrorCode::OriginMismatch);
    }

    #[test]
    fn test_map_not_found_to_code() {
        let error = HostedApiError::not_found("session:abc-123");
        let code = map_error_to_code(&error);
        assert_eq!(code, ErrorCode::SessionNotFound);

        let error2 = HostedApiError::not_found("public_key:pk-test");
        let code2 = map_error_to_code(&error2);
        assert_eq!(code2, ErrorCode::PublicKeyNotFound);
    }

    #[test]
    fn test_map_gone_to_code() {
        let error = HostedApiError::gone("Session has expired");
        let code = map_error_to_code(&error);
        assert_eq!(code, ErrorCode::SessionExpired);

        let error2 = HostedApiError::gone("Session has been revoked");
        let code2 = map_error_to_code(&error2);
        assert_eq!(code2, ErrorCode::SessionRevoked);
    }

    #[test]
    fn test_map_internal_error_to_code() {
        // EIL-021: All internal errors map to generic InternalServerError
        // regardless of message content (no subsystem leak via error code).
        let error = HostedApiError::internal("Database connection failed");
        let code = map_error_to_code(&error);
        assert_eq!(code, ErrorCode::InternalServerError);

        let error2 = HostedApiError::internal("Encryption failed");
        let code2 = map_error_to_code(&error2);
        assert_eq!(code2, ErrorCode::InternalServerError);
    }

    #[test]
    fn test_error_response_with_code() {
        let error = HostedApiError::invalid_request("Invalid session ID");
        let response = ErrorResponseWithCode::from_hosted_api_error(error, "req-123".to_string());

        assert_eq!(response.code, ErrorCode::InvalidSessionId);
        assert_eq!(response.request_id, "req-123");
        assert!(response.error.contains("Invalid session ID"));
    }

    #[test]
    fn test_error_response_canonical_shape() -> Result<(), Box<dyn std::error::Error>> {
        let error = HostedApiError::rate_limit_exceeded(60, 100, 60);
        let response = ErrorResponseWithCode::from_hosted_api_error(error, "req-456".to_string());

        assert_eq!(response.code, ErrorCode::RateLimitExceeded);

        // Verify canonical JSON shape: {"error":"...","code":"...","request_id":"..."}
        let json = serde_json::to_value(&response)?;
        let obj = json.as_object().ok_or("expected JSON object")?;
        assert!(obj.contains_key("error"), "missing 'error' field");
        assert!(obj.contains_key("code"), "missing 'code' field");
        assert!(obj.contains_key("request_id"), "missing 'request_id' field");
        assert_eq!(obj.len(), 3, "expected exactly 3 fields");
        Ok(())
    }

    #[test]
    fn test_error_code_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let code = ErrorCode::SessionExpired;
        let json = serde_json::to_string(&code)?;
        assert_eq!(json, r#""SESSION_EXPIRED""#);

        let deserialized: ErrorCode = serde_json::from_str(&json)?;
        assert_eq!(deserialized, code);
        Ok(())
    }

    // ── description() exhaustive coverage ──────────────────────────────

    #[test]
    fn test_description_400_variants() {
        assert_eq!(
            ErrorCode::InvalidRequest.description(),
            "The request format or parameters are invalid"
        );
        assert_eq!(
            ErrorCode::InvalidCodeVerifier.description(),
            "The PKCE code verifier is invalid"
        );
        assert_eq!(
            ErrorCode::InvalidOrigin.description(),
            "The Origin header is invalid"
        );
        assert_eq!(
            ErrorCode::InvalidPublicKey.description(),
            "The public key format is invalid"
        );
        assert_eq!(
            ErrorCode::MissingRequiredField.description(),
            "A required field is missing"
        );
        assert_eq!(
            ErrorCode::InvalidFieldFormat.description(),
            "A field has an invalid format"
        );
    }

    #[test]
    fn test_description_401_variants() {
        assert_eq!(
            ErrorCode::AuthenticationRequired.description(),
            "Authentication is required for this operation"
        );
        assert_eq!(
            ErrorCode::InvalidCredentials.description(),
            "The provided credentials are invalid"
        );
        assert_eq!(
            ErrorCode::PkceVerificationFailed.description(),
            "PKCE code verifier verification failed"
        );
        assert_eq!(
            ErrorCode::InvalidSessionToken.description(),
            "The session token is invalid or expired"
        );
        assert_eq!(
            ErrorCode::InvalidAdminKey.description(),
            "The admin key is invalid or expired"
        );
    }

    #[test]
    fn test_description_403_variants() {
        assert_eq!(
            ErrorCode::InsufficientPermissions.description(),
            "You do not have sufficient permissions"
        );
        assert_eq!(
            ErrorCode::SessionOwnershipDenied.description(),
            "You do not own this session"
        );
        assert_eq!(
            ErrorCode::OriginMismatch.description(),
            "Request origin does not match session origin"
        );
        assert_eq!(
            ErrorCode::OperationNotAllowed.description(),
            "This operation is not allowed in the current state"
        );
        assert_eq!(
            ErrorCode::ReauthRequired.description(),
            "Re-authentication is required for this sensitive operation"
        );
    }

    #[test]
    fn test_description_404_405_409_410_variants() {
        assert_eq!(
            ErrorCode::ResourceNotFound.description(),
            "The requested resource was not found"
        );
        assert_eq!(
            ErrorCode::PublicKeyNotFound.description(),
            "The public key was not found"
        );
        assert_eq!(
            ErrorCode::MethodNotAllowed.description(),
            "The HTTP method is not allowed for this endpoint"
        );
        assert_eq!(
            ErrorCode::SessionAlreadyRedeemed.description(),
            "This session has already been redeemed"
        );
        assert_eq!(
            ErrorCode::ResourceAlreadyExists.description(),
            "The resource already exists"
        );
        assert_eq!(
            ErrorCode::StateConflict.description(),
            "The request conflicts with the current state"
        );
        assert_eq!(
            ErrorCode::SessionRevoked.description(),
            "The session has been revoked"
        );
        assert_eq!(
            ErrorCode::ResourceGone.description(),
            "The resource is no longer available"
        );
    }

    #[test]
    fn test_description_402_429_5xx_variants() {
        assert_eq!(
            ErrorCode::InsufficientCredits.description(),
            "Insufficient credits for this operation"
        );
        assert_eq!(
            ErrorCode::TooManyRedemptionAttempts.description(),
            "Too many redemption attempts"
        );
        assert_eq!(
            ErrorCode::TooManyStatusChecks.description(),
            "Too many status check requests"
        );
        assert_eq!(
            ErrorCode::DatabaseError.description(),
            "A database error occurred"
        );
        assert_eq!(
            ErrorCode::StorageError.description(),
            "A storage error occurred"
        );
        assert_eq!(
            ErrorCode::EncryptionError.description(),
            "An encryption error occurred"
        );
        assert_eq!(
            ErrorCode::TokenSigningError.description(),
            "A token signing error occurred"
        );
        assert_eq!(
            ErrorCode::CircuitBreakerOpen.description(),
            "The circuit breaker is open"
        );
        assert_eq!(
            ErrorCode::ServiceDegraded.description(),
            "The service is running in degraded mode"
        );
        assert_eq!(
            ErrorCode::ProviiVerifierTimeout.description(),
            "The provii-verifier service timed out"
        );
    }

    // ── http_status() exhaustive coverage ──────────────────────────────

    #[test]
    fn test_http_status_all_400_variants() {
        assert_eq!(ErrorCode::InvalidSessionId.http_status(), 400);
        assert_eq!(ErrorCode::InvalidCodeVerifier.http_status(), 400);
        assert_eq!(ErrorCode::InvalidOrigin.http_status(), 400);
        assert_eq!(ErrorCode::InvalidPublicKey.http_status(), 400);
        assert_eq!(ErrorCode::MissingRequiredField.http_status(), 400);
        assert_eq!(ErrorCode::InvalidFieldFormat.http_status(), 400);
    }

    #[test]
    fn test_http_status_all_401_variants() {
        assert_eq!(ErrorCode::InvalidCredentials.http_status(), 401);
        assert_eq!(ErrorCode::PkceVerificationFailed.http_status(), 401);
        assert_eq!(ErrorCode::InvalidSessionToken.http_status(), 401);
        assert_eq!(ErrorCode::InvalidAdminKey.http_status(), 401);
    }

    #[test]
    fn test_http_status_all_403_variants() {
        assert_eq!(ErrorCode::InsufficientPermissions.http_status(), 403);
        assert_eq!(ErrorCode::SessionOwnershipDenied.http_status(), 403);
        assert_eq!(ErrorCode::OriginMismatch.http_status(), 403);
        assert_eq!(ErrorCode::OperationNotAllowed.http_status(), 403);
        assert_eq!(ErrorCode::ReauthRequired.http_status(), 403);
    }

    #[test]
    fn test_http_status_remaining_codes() {
        assert_eq!(ErrorCode::ResourceNotFound.http_status(), 404);
        assert_eq!(ErrorCode::PublicKeyNotFound.http_status(), 404);
        assert_eq!(ErrorCode::MethodNotAllowed.http_status(), 405);
        assert_eq!(ErrorCode::SessionAlreadyRedeemed.http_status(), 409);
        assert_eq!(ErrorCode::ResourceAlreadyExists.http_status(), 409);
        assert_eq!(ErrorCode::StateConflict.http_status(), 409);
        assert_eq!(ErrorCode::SessionExpired.http_status(), 410);
        assert_eq!(ErrorCode::SessionRevoked.http_status(), 410);
        assert_eq!(ErrorCode::ResourceGone.http_status(), 410);
        assert_eq!(ErrorCode::InsufficientCredits.http_status(), 402);
        assert_eq!(ErrorCode::TooManyRedemptionAttempts.http_status(), 429);
        assert_eq!(ErrorCode::TooManyStatusChecks.http_status(), 429);
        assert_eq!(ErrorCode::DatabaseError.http_status(), 500);
        assert_eq!(ErrorCode::StorageError.http_status(), 500);
        assert_eq!(ErrorCode::EncryptionError.http_status(), 500);
        assert_eq!(ErrorCode::TokenSigningError.http_status(), 500);
        assert_eq!(ErrorCode::ServiceUnavailable.http_status(), 503);
        assert_eq!(ErrorCode::CircuitBreakerOpen.http_status(), 503);
        assert_eq!(ErrorCode::ServiceDegraded.http_status(), 503);
        assert_eq!(ErrorCode::GatewayTimeout.http_status(), 504);
        assert_eq!(ErrorCode::ProviiVerifierTimeout.http_status(), 504);
    }

    // ── as_str() exhaustive coverage ───────────────────────────────────

    #[test]
    fn test_as_str_all_400_variants() {
        assert_eq!(ErrorCode::InvalidRequest.as_str(), "INVALID_REQUEST");
        assert_eq!(
            ErrorCode::InvalidCodeVerifier.as_str(),
            "INVALID_CODE_VERIFIER"
        );
        assert_eq!(ErrorCode::InvalidOrigin.as_str(), "INVALID_ORIGIN");
        assert_eq!(ErrorCode::InvalidPublicKey.as_str(), "INVALID_PUBLIC_KEY");
        assert_eq!(
            ErrorCode::MissingRequiredField.as_str(),
            "MISSING_REQUIRED_FIELD"
        );
        assert_eq!(
            ErrorCode::InvalidFieldFormat.as_str(),
            "INVALID_FIELD_FORMAT"
        );
    }

    #[test]
    fn test_as_str_all_auth_variants() {
        assert_eq!(
            ErrorCode::AuthenticationRequired.as_str(),
            "AUTHENTICATION_REQUIRED"
        );
        assert_eq!(
            ErrorCode::InvalidCredentials.as_str(),
            "INVALID_CREDENTIALS"
        );
        assert_eq!(
            ErrorCode::PkceVerificationFailed.as_str(),
            "PKCE_VERIFICATION_FAILED"
        );
        assert_eq!(
            ErrorCode::InvalidSessionToken.as_str(),
            "INVALID_SESSION_TOKEN"
        );
        assert_eq!(ErrorCode::InvalidAdminKey.as_str(), "INVALID_ADMIN_KEY");
        assert_eq!(ErrorCode::AccessDenied.as_str(), "ACCESS_DENIED");
        assert_eq!(
            ErrorCode::InsufficientPermissions.as_str(),
            "INSUFFICIENT_PERMISSIONS"
        );
        assert_eq!(
            ErrorCode::SessionOwnershipDenied.as_str(),
            "SESSION_OWNERSHIP_DENIED"
        );
        assert_eq!(ErrorCode::OriginMismatch.as_str(), "ORIGIN_MISMATCH");
        assert_eq!(
            ErrorCode::OperationNotAllowed.as_str(),
            "OPERATION_NOT_ALLOWED"
        );
        assert_eq!(ErrorCode::ReauthRequired.as_str(), "REAUTH_REQUIRED");
    }

    #[test]
    fn test_as_str_remaining_variants() {
        assert_eq!(ErrorCode::SessionNotFound.as_str(), "SESSION_NOT_FOUND");
        assert_eq!(ErrorCode::ResourceNotFound.as_str(), "RESOURCE_NOT_FOUND");
        assert_eq!(
            ErrorCode::PublicKeyNotFound.as_str(),
            "PUBLIC_KEY_NOT_FOUND"
        );
        assert_eq!(ErrorCode::MethodNotAllowed.as_str(), "METHOD_NOT_ALLOWED");
        assert_eq!(
            ErrorCode::SessionAlreadyRedeemed.as_str(),
            "SESSION_ALREADY_REDEEMED"
        );
        assert_eq!(
            ErrorCode::ResourceAlreadyExists.as_str(),
            "RESOURCE_ALREADY_EXISTS"
        );
        assert_eq!(ErrorCode::StateConflict.as_str(), "STATE_CONFLICT");
        assert_eq!(ErrorCode::SessionRevoked.as_str(), "SESSION_REVOKED");
        assert_eq!(ErrorCode::ResourceGone.as_str(), "RESOURCE_GONE");
        assert_eq!(
            ErrorCode::InsufficientCredits.as_str(),
            "INSUFFICIENT_CREDITS"
        );
        assert_eq!(
            ErrorCode::TooManyRedemptionAttempts.as_str(),
            "TOO_MANY_REDEMPTION_ATTEMPTS"
        );
        assert_eq!(
            ErrorCode::TooManyStatusChecks.as_str(),
            "TOO_MANY_STATUS_CHECKS"
        );
        assert_eq!(
            ErrorCode::InternalServerError.as_str(),
            "INTERNAL_SERVER_ERROR"
        );
        assert_eq!(ErrorCode::DatabaseError.as_str(), "DATABASE_ERROR");
        assert_eq!(ErrorCode::StorageError.as_str(), "STORAGE_ERROR");
        assert_eq!(ErrorCode::EncryptionError.as_str(), "ENCRYPTION_ERROR");
        assert_eq!(ErrorCode::TokenSigningError.as_str(), "TOKEN_SIGNING_ERROR");
        assert_eq!(
            ErrorCode::ServiceUnavailable.as_str(),
            "SERVICE_UNAVAILABLE"
        );
        assert_eq!(
            ErrorCode::CircuitBreakerOpen.as_str(),
            "CIRCUIT_BREAKER_OPEN"
        );
        assert_eq!(ErrorCode::ServiceDegraded.as_str(), "SERVICE_DEGRADED");
        assert_eq!(ErrorCode::GatewayTimeout.as_str(), "GATEWAY_TIMEOUT");
        assert_eq!(
            ErrorCode::ProviiVerifierTimeout.as_str(),
            "PROVII_VERIFIER_TIMEOUT"
        );
    }

    // ── map_error_to_code branches not yet covered ─────────────────────

    #[test]
    fn test_map_invalid_request_origin_case_sensitive() {
        // Covers the "Origin" (capital O) branch
        let error = HostedApiError::invalid_request("Invalid Origin header");
        assert_eq!(map_error_to_code(&error), ErrorCode::InvalidOrigin);
    }

    #[test]
    fn test_map_invalid_request_public_key_underscore() {
        // Covers the "public_key" branch
        let error = HostedApiError::invalid_request("Invalid public_key format");
        assert_eq!(map_error_to_code(&error), ErrorCode::InvalidPublicKey);
    }

    #[test]
    fn test_map_invalid_request_generic_fallback() {
        let error = HostedApiError::invalid_request("Something went wrong");
        assert_eq!(map_error_to_code(&error), ErrorCode::InvalidRequest);
    }

    #[test]
    fn test_map_invalid_request_required_keyword() {
        let error = HostedApiError::invalid_request("Field is required");
        assert_eq!(map_error_to_code(&error), ErrorCode::MissingRequiredField);
    }

    #[test]
    fn test_map_invalid_request_verifier_keyword() {
        let error = HostedApiError::invalid_request("Invalid code verifier");
        assert_eq!(map_error_to_code(&error), ErrorCode::InvalidCodeVerifier);
    }

    #[test]
    fn test_map_invalid_request_public_key_space() {
        let error = HostedApiError::invalid_request("Invalid public key");
        assert_eq!(map_error_to_code(&error), ErrorCode::InvalidPublicKey);
    }

    #[test]
    fn test_map_unauthorized_token_keyword() {
        let error = HostedApiError::unauthorized("Invalid session token");
        assert_eq!(map_error_to_code(&error), ErrorCode::InvalidSessionToken);
    }

    #[test]
    fn test_map_unauthorized_generic_fallback() {
        let error = HostedApiError::unauthorized("Bad credentials");
        assert_eq!(map_error_to_code(&error), ErrorCode::InvalidCredentials);
    }

    #[test]
    fn test_map_unauthorized_verifier_keyword() {
        let error = HostedApiError::unauthorized("Code verifier mismatch");
        assert_eq!(map_error_to_code(&error), ErrorCode::PkceVerificationFailed);
    }

    #[test]
    fn test_map_forbidden_reauth_variants() {
        let e1 = HostedApiError::forbidden("Re-authentication is required");
        assert_eq!(map_error_to_code(&e1), ErrorCode::ReauthRequired);

        let e2 = HostedApiError::forbidden("Please re-authenticate");
        assert_eq!(map_error_to_code(&e2), ErrorCode::ReauthRequired);
    }

    #[test]
    fn test_map_forbidden_permission_keyword() {
        let error = HostedApiError::forbidden("Insufficient permission for this action");
        assert_eq!(
            map_error_to_code(&error),
            ErrorCode::InsufficientPermissions
        );
    }

    #[test]
    fn test_map_forbidden_generic_fallback() {
        let error = HostedApiError::forbidden("Nope");
        assert_eq!(map_error_to_code(&error), ErrorCode::AccessDenied);
    }

    #[test]
    fn test_map_forbidden_ownership_keyword() {
        let error = HostedApiError::forbidden("Session ownership denied");
        assert_eq!(map_error_to_code(&error), ErrorCode::SessionOwnershipDenied);
    }

    #[test]
    fn test_map_not_found_generic_fallback() {
        let error = HostedApiError::not_found("widget:xyz");
        assert_eq!(map_error_to_code(&error), ErrorCode::ResourceNotFound);
    }

    #[test]
    fn test_map_not_found_key_keyword() {
        // "key" without "public_key" prefix still matches PublicKeyNotFound
        let error = HostedApiError::not_found("key:abc");
        assert_eq!(map_error_to_code(&error), ErrorCode::PublicKeyNotFound);
    }

    #[test]
    fn test_map_conflict_exists_keyword() {
        let error = HostedApiError::conflict("Resource already exists");
        assert_eq!(map_error_to_code(&error), ErrorCode::ResourceAlreadyExists);
    }

    #[test]
    fn test_map_conflict_generic_fallback() {
        let error = HostedApiError::conflict("Some state conflict");
        assert_eq!(map_error_to_code(&error), ErrorCode::StateConflict);
    }

    #[test]
    fn test_map_gone_generic_fallback() {
        let error = HostedApiError::gone("Resource is gone");
        assert_eq!(map_error_to_code(&error), ErrorCode::ResourceGone);
    }

    #[test]
    fn test_map_method_not_allowed() {
        let error = HostedApiError::MethodNotAllowed {
            allowed: vec!["GET".to_string()],
        };
        assert_eq!(map_error_to_code(&error), ErrorCode::MethodNotAllowed);
    }

    #[test]
    fn test_map_rate_limit_exceeded() {
        let error = HostedApiError::rate_limit_exceeded(30, 100, 60);
        assert_eq!(map_error_to_code(&error), ErrorCode::RateLimitExceeded);
    }

    #[test]
    fn test_map_insufficient_credits() {
        let error = HostedApiError::insufficient_credits("No credits left");
        assert_eq!(map_error_to_code(&error), ErrorCode::InsufficientCredits);
    }

    // EIL-021: Internal errors must not leak subsystem details
    #[test]
    fn test_eil021_service_unavailable_generic() {
        let error = HostedApiError::service_unavailable("Circuit breaker tripped on KV store");
        assert_eq!(map_error_to_code(&error), ErrorCode::ServiceUnavailable);
    }

    #[test]
    fn test_eil021_gateway_timeout_generic() {
        let error = HostedApiError::gateway_timeout("provii-verifier");
        assert_eq!(map_error_to_code(&error), ErrorCode::GatewayTimeout);
    }

    // ── serde roundtrip for all variants ───────────────────────────────

    #[test]
    fn test_error_code_serde_roundtrip_all_variants() -> Result<(), Box<dyn std::error::Error>> {
        let variants = vec![
            ErrorCode::InvalidRequest,
            ErrorCode::InvalidSessionId,
            ErrorCode::InvalidCodeVerifier,
            ErrorCode::InvalidOrigin,
            ErrorCode::InvalidPublicKey,
            ErrorCode::MissingRequiredField,
            ErrorCode::InvalidFieldFormat,
            ErrorCode::AuthenticationRequired,
            ErrorCode::InvalidCredentials,
            ErrorCode::PkceVerificationFailed,
            ErrorCode::InvalidSessionToken,
            ErrorCode::InvalidAdminKey,
            ErrorCode::AccessDenied,
            ErrorCode::InsufficientPermissions,
            ErrorCode::SessionOwnershipDenied,
            ErrorCode::OriginMismatch,
            ErrorCode::OperationNotAllowed,
            ErrorCode::ReauthRequired,
            ErrorCode::SessionNotFound,
            ErrorCode::ResourceNotFound,
            ErrorCode::PublicKeyNotFound,
            ErrorCode::MethodNotAllowed,
            ErrorCode::SessionAlreadyRedeemed,
            ErrorCode::ResourceAlreadyExists,
            ErrorCode::StateConflict,
            ErrorCode::SessionExpired,
            ErrorCode::SessionRevoked,
            ErrorCode::ResourceGone,
            ErrorCode::InsufficientCredits,
            ErrorCode::RateLimitExceeded,
            ErrorCode::TooManyRedemptionAttempts,
            ErrorCode::TooManyStatusChecks,
            ErrorCode::InternalServerError,
            ErrorCode::DatabaseError,
            ErrorCode::StorageError,
            ErrorCode::EncryptionError,
            ErrorCode::TokenSigningError,
            ErrorCode::ServiceUnavailable,
            ErrorCode::CircuitBreakerOpen,
            ErrorCode::ServiceDegraded,
            ErrorCode::GatewayTimeout,
            ErrorCode::ProviiVerifierTimeout,
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant)?;
            let deserialized: ErrorCode = serde_json::from_str(&json)?;
            assert_eq!(deserialized, variant, "roundtrip failed for {:?}", variant);
        }
        Ok(())
    }

    // ── ErrorResponseWithCode additional coverage ──────────────────────

    #[test]
    fn test_error_response_from_internal_error() {
        let error = HostedApiError::internal("DB failure");
        let resp = ErrorResponseWithCode::from_hosted_api_error(error, "req-int".to_string());
        assert_eq!(resp.code, ErrorCode::InternalServerError);
        assert_eq!(resp.request_id, "req-int");
    }

    #[test]
    fn test_error_response_from_forbidden() {
        let error = HostedApiError::forbidden("origin mismatch");
        let resp = ErrorResponseWithCode::from_hosted_api_error(error, "req-fb".to_string());
        assert_eq!(resp.code, ErrorCode::OriginMismatch);
    }

    #[test]
    fn test_error_response_from_gone() {
        let error = HostedApiError::gone("Session has expired");
        let resp = ErrorResponseWithCode::from_hosted_api_error(error, "req-gone".to_string());
        assert_eq!(resp.code, ErrorCode::SessionExpired);
        assert!(resp.error.contains("expired"));
    }

    #[test]
    fn test_error_response_from_conflict() {
        let error = HostedApiError::conflict("Already redeemed");
        let resp = ErrorResponseWithCode::from_hosted_api_error(error, "req-conf".to_string());
        assert_eq!(resp.code, ErrorCode::SessionAlreadyRedeemed);
    }

    #[test]
    fn test_error_response_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let error = HostedApiError::not_found("session:test");
        let resp = ErrorResponseWithCode::from_hosted_api_error(error, "req-rt".to_string());
        let json = serde_json::to_string(&resp)?;
        let deserialized: ErrorResponseWithCode = serde_json::from_str(&json)?;
        assert_eq!(deserialized.code, ErrorCode::SessionNotFound);
        assert_eq!(deserialized.request_id, "req-rt");
        Ok(())
    }

    // ── as_str consistency with serde ──────────────────────────────────

    #[test]
    fn test_as_str_matches_serde_output() -> Result<(), Box<dyn std::error::Error>> {
        // as_str() should produce the same SCREAMING_SNAKE_CASE as serde
        let code = ErrorCode::InternalServerError;
        let serde_str = serde_json::to_string(&code)?;
        // serde wraps in quotes
        let expected = format!("\"{}\"", code.as_str());
        assert_eq!(serde_str, expected);
        Ok(())
    }

    // ── ErrorCode derives ──────────────────────────────────────────────

    #[test]
    fn test_error_code_clone_and_copy() {
        let code = ErrorCode::SessionExpired;
        let cloned = code;
        let copied = code;
        assert_eq!(code, cloned);
        assert_eq!(code, copied);
    }

    #[test]
    fn test_error_code_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ErrorCode::InvalidRequest);
        set.insert(ErrorCode::InvalidRequest);
        set.insert(ErrorCode::SessionNotFound);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_error_code_debug() {
        let debug = format!("{:?}", ErrorCode::GatewayTimeout);
        assert_eq!(debug, "GatewayTimeout");
    }
}
