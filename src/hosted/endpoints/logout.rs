// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! User logout endpoint.
//!
//! `POST /v1/hosted/user/logout` terminates the user's session by clearing
//! the session cookie and issuing a `Clear-Site-Data` header for full
//! client-side cleanup.
//!
//! SECURITY: The endpoint uses POST to prevent CSRF via simple GET requests.
//! The session cookie is expired with `Max-Age=0` while preserving all
//! `__Host-` prefix requirements (Secure, HttpOnly, Path=/, no Domain).
//! `Clear-Site-Data` provides defence in depth by wiping cache, cookies, and
//! storage. No server-side session lookup is needed because sessions are
//! stateless (HMAC-signed tokens).
//!
//! Satisfies ASVS 7.4.1 \[L1\] (session termination), 7.4.4 \[L2\] (cookie
//! clearing), and 14.3.1 \[L1\] (Clear-Site-Data).
//!
//! No service binding is involved; this handler is ported as-is from
//! provii-verifier.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use worker::{Error as WorkerError, Response};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// JSON body returned by the logout endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutResponse {
    /// Logout outcome, always `"logged_out"` on success.
    pub status: String,

    /// Human-readable confirmation message.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `POST /v1/hosted/user/logout`.
///
/// Terminates the user's session by clearing the session cookie and all
/// client-side data. Does not require authentication: sessions are stateless
/// (HMAC-signed tokens), so no server-side cleanup is needed. Works even if
/// the session cookie is already invalid or expired.
///
/// SECURITY: Cookie expiration preserves all `__Host-` prefix attributes
/// (Secure, HttpOnly, SameSite=None, Path=/). `Clear-Site-Data` clears cache,
/// cookies, and storage as defence in depth. No sensitive information appears
/// in the response body.
///
/// TODO(testing): ADV-VA-06-012 -- cookie expiration attributes and
/// Clear-Site-Data header emission lack integration tests.
pub async fn handle_hosted_logout(cookie_name: &str) -> Result<Response, WorkerError> {
    let logout_response = LogoutResponse {
        status: "logged_out".to_string(),
        message: "Successfully logged out".to_string(),
    };

    let mut response = Response::from_json(&logout_response)?;

    // SECURITY: Expire the session cookie with Max-Age=0. All __Host- prefix
    // attributes must be preserved (Secure, HttpOnly, SameSite=None, Path=/, no
    // Domain). The cookie name comes from SESSION_COOKIE_NAME env var so both
    // sandbox (__Host-session-sandbox) and production (__Host-session) work.
    // Uses CookieConfig for consistent attributes across all endpoints.
    let cookie_cfg = crate::hosted::cookie::CookieConfig::new()
        .with_name(cookie_name.to_string())
        .with_max_age(0);
    response.headers_mut().set(
        "Set-Cookie",
        &crate::hosted::cookie::generate_session_cookie("", &cookie_cfg),
    )?;

    // SECURITY: Clear-Site-Data wipes cache, cookies, and storage for the
    // origin (ASVS 14.3.1 [L1]).
    response
        .headers_mut()
        .set("Clear-Site-Data", "\"cache\", \"cookies\", \"storage\"")?;

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logout_response_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let response = LogoutResponse {
            status: "logged_out".to_string(),
            message: "Successfully logged out".to_string(),
        };

        let json = serde_json::to_string(&response)?;
        assert!(json.contains("logged_out"));
        assert!(json.contains("Successfully logged out"));
        Ok(())
    }

    #[test]
    fn test_logout_response_structure() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"status":"logged_out","message":"Successfully logged out"}"#;
        let response: LogoutResponse = serde_json::from_str(json)?;
        assert_eq!(response.status, "logged_out");
        assert_eq!(response.message, "Successfully logged out");
        Ok(())
    }

    #[test]
    fn test_logout_response_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = LogoutResponse {
            status: "logged_out".to_string(),
            message: "Successfully logged out".to_string(),
        };
        let json = serde_json::to_string(&original)?;
        let deserialized: LogoutResponse = serde_json::from_str(&json)?;
        assert_eq!(deserialized.status, original.status);
        assert_eq!(deserialized.message, original.message);
        Ok(())
    }

    #[test]
    fn test_logout_response_clone() {
        let original = LogoutResponse {
            status: "logged_out".to_string(),
            message: "msg".to_string(),
        };
        let cloned = original.clone();
        assert_eq!(cloned.status, "logged_out");
        assert_eq!(cloned.message, "msg");
    }

    #[test]
    fn test_logout_response_debug() {
        let response = LogoutResponse {
            status: "logged_out".to_string(),
            message: "Successfully logged out".to_string(),
        };
        let debug_str = format!("{:?}", response);
        assert!(debug_str.contains("LogoutResponse"));
        assert!(debug_str.contains("logged_out"));
    }

    #[test]
    fn test_logout_response_deserialize_extra_fields() -> Result<(), Box<dyn std::error::Error>> {
        // LogoutResponse does NOT have deny_unknown_fields, so extra fields are ignored.
        let json = r#"{"status":"logged_out","message":"msg","extra":"field"}"#;
        let response: LogoutResponse = serde_json::from_str(json)?;
        assert_eq!(response.status, "logged_out");
        assert_eq!(response.message, "msg");
        Ok(())
    }

    #[test]
    fn test_logout_response_deserialize_missing_field() {
        let json = r#"{"status":"logged_out"}"#;
        let result = serde_json::from_str::<LogoutResponse>(json);
        assert!(result.is_err(), "missing 'message' field should fail");
    }

    #[test]
    fn test_logout_response_empty_strings() -> Result<(), Box<dyn std::error::Error>> {
        let response = LogoutResponse {
            status: String::new(),
            message: String::new(),
        };
        let json = serde_json::to_string(&response)?;
        let deserialized: LogoutResponse = serde_json::from_str(&json)?;
        assert_eq!(deserialized.status, "");
        assert_eq!(deserialized.message, "");
        Ok(())
    }

    #[test]
    fn test_logout_response_json_field_names() -> Result<(), Box<dyn std::error::Error>> {
        let response = LogoutResponse {
            status: "s".to_string(),
            message: "m".to_string(),
        };
        let json = serde_json::to_string(&response)?;
        // Verify exact field names in serialised JSON.
        let val: serde_json::Value = serde_json::from_str(&json)?;
        assert!(val.get("status").is_some(), "field must be named 'status'");
        assert!(
            val.get("message").is_some(),
            "field must be named 'message'"
        );
        Ok(())
    }
}
