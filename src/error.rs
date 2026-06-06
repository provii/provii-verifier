// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Typed API errors and their conversion to structured HTTP responses.
//!
//! Every error variant maps to a specific HTTP status code, a machine-readable
//! error code, and a safe human-readable message. Security-relevant errors are
//! additionally logged for audit (ASVS V7.2.1).
#![forbid(unsafe_code)]

use serde::Serialize;
use thiserror::Error;
use worker::{Error as WorkerError, Response};

/// Convenience alias for route handler return types.
pub type ApiResult<T> = std::result::Result<T, ApiError>;

/// Structured diagnostic payload attached to an [`ApiError`].
///
/// `code` is a machine-readable identifier (e.g. `ORIGIN_MISSING`,
/// `INVALID_PKCE_CHALLENGE`) that overrides the variant's default code in the
/// JSON response. `field` names the offending request field where applicable.
/// `detail` is a safe human-readable explanation that never leaks secret
/// material.
///
/// Construction uses [`ApiError::bad_request`], [`ApiError::forbidden`],
/// etc. The detail string is what the existing `Option<String>` payload carried,
/// so older constructors (`ApiError::BadRequest(Some("foo".into()))`) keep
/// working unchanged via the `From<String>` impl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDetail {
    pub code: Option<String>,
    pub field: Option<String>,
    pub detail: Option<String>,
}

impl ErrorDetail {
    pub fn new() -> Self {
        Self {
            code: None,
            field: None,
            detail: None,
        }
    }

    pub fn code(mut self, c: &str) -> Self {
        self.code = Some(c.to_string());
        self
    }

    pub fn field(mut self, f: impl Into<String>) -> Self {
        self.field = Some(f.into());
        self
    }

    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }
}

impl Default for ErrorDetail {
    fn default() -> Self {
        Self::new()
    }
}

/// Implicit lift from a bare detail string used by the legacy
/// `ApiError::BadRequest(Some("...".into()))` call sites. No code or field is
/// attached.
impl From<String> for ErrorDetail {
    fn from(s: String) -> Self {
        Self {
            code: None,
            field: None,
            detail: Some(s),
        }
    }
}

impl From<&str> for ErrorDetail {
    fn from(s: &str) -> Self {
        Self::from(s.to_string())
    }
}

// W7-B3: All error responses MUST emit the canonical 5-key envelope
// `{error, code, field, detail, request_id}`. Wave 7 found that schema-validation
// paths emitted 5 keys while CSRF rejection emitted 2 keys and NOT_FOUND emitted
// 3 keys. The previous `skip_serializing_if` on `field` and `detail` collapsed
// optional fields, breaking client parsers that expected uniform shape.
//
// `code` is always set by every emit site (both `to_response` and
// `build_error_response_full` populate it from the variant default), so the
// existing skip-if-none is preserved only as a defensive guard; in practice
// the field is always present in serialised output.
#[derive(Serialize)]
struct ErrorBody {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    field: Option<String>,
    detail: Option<String>,
    request_id: String,
}

/// Enumeration of all API error responses returned by the verifier worker.
///
/// Each variant carries an optional diagnostic message (never exposed to
/// callers) and maps to a fixed HTTP status code via [`ApiError::to_response`].
/// Sentinel prefix used to embed a structured `ErrorDetail` inside the legacy
/// `Option<String>` payload. The format is
/// `__SD__|<code>|<field>|<detail>` so call sites that destructure
/// `ApiError::BadRequest(Some(msg))` keep compiling unchanged while new call
/// sites carry machine-readable diagnostic fields.
const STRUCTURED_DETAIL_SENTINEL: &str = "__SD__";

#[derive(Debug, Error)]
pub enum ApiError {
    /// 400: Malformed or invalid request payload.
    #[error("bad-request")]
    BadRequest(Option<String>),

    /// 404: Requested resource does not exist.
    #[error("not-found")]
    NotFound,

    /// 409: Request conflicts with current server state.
    #[error("conflict")]
    Conflict(Option<String>),

    /// 410: Resource existed but has been permanently removed (e.g. expired challenge).
    #[error("gone")]
    Gone(Option<String>),

    /// 400: Zero knowledge proof verified but the claim was not satisfied.
    #[error("verification-failed")]
    VerificationFailed,

    /// 400: Proof bytes could not be deserialised or are structurally invalid.
    #[error("invalid-proof")]
    InvalidProof,

    /// 401: Missing or invalid authentication credentials.
    #[error("unauthorized")]
    Unauthorized,

    /// 403: Authenticated caller lacks permission for the requested operation.
    #[error("forbidden")]
    Forbidden(Option<String>),

    /// 413: Request body exceeds the configured size limit.
    #[error("payload-too-large")]
    PayloadTooLarge(Option<String>),

    /// 415: Content-Type header is not `application/json`.
    #[error("unsupported-media-type")]
    UnsupportedMediaType,

    /// 429: Origin or IP has exceeded its rate limit window.
    #[error("too-many-requests")]
    TooManyRequests(Option<String>),

    /// 402: Relying party has insufficient verification credits.
    #[error("payment-required")]
    PaymentRequired(Option<String>),

    /// 503: Downstream dependency is temporarily unavailable.
    #[error("service-unavailable")]
    ServiceUnavailable(Option<String>),

    /// 500: Unrecoverable internal failure, automatically converted from `anyhow::Error`.
    #[error("internal-server-error")]
    Internal(#[from] anyhow::Error),
}

/// Encode a structured detail into the sentinel format used for the
/// `Option<String>` payload of every `ApiError` variant. Call sites use the
/// `bad_request_with`, `forbidden_with`, etc. constructors instead of building
/// this string directly.
fn encode_structured_detail(d: &ErrorDetail) -> String {
    let code = d.code.as_deref().unwrap_or("");
    let field = d.field.as_deref().unwrap_or("").replace('|', "/");
    let detail = d.detail.as_deref().unwrap_or("").replace('|', "/");
    format!(
        "{}|{}|{}|{}",
        STRUCTURED_DETAIL_SENTINEL, code, field, detail
    )
}

/// Decode a sentinel-encoded structured detail. Returns `None` when the input
/// does not start with the sentinel (i.e. it is a legacy free-form message).
fn decode_structured_detail(s: &str) -> Option<ErrorDetail> {
    let mut parts = s.splitn(4, '|');
    let head = parts.next()?;
    if head != STRUCTURED_DETAIL_SENTINEL {
        return None;
    }
    let code = parts.next().unwrap_or("");
    let field = parts.next().unwrap_or("");
    let detail = parts.next().unwrap_or("");
    Some(ErrorDetail {
        code: if code.is_empty() {
            None
        } else {
            Some(code.to_string())
        },
        field: if field.is_empty() {
            None
        } else {
            Some(field.to_string())
        },
        detail: if detail.is_empty() {
            None
        } else {
            Some(detail.to_string())
        },
    })
}

impl ApiError {
    /// Build a 400 BadRequest carrying a structured `code`, optional `field`,
    /// and human-readable `detail`. The detail string is sent verbatim in the
    /// JSON body and MUST NOT contain secret material (API keys, HMAC tags,
    /// nonces, PKCE verifiers, etc.).
    pub fn bad_request(code: &'static str, field: Option<&str>, detail: impl Into<String>) -> Self {
        let mut d = ErrorDetail::new().code(code).detail(detail);
        if let Some(f) = field {
            d = d.field(f);
        }
        ApiError::BadRequest(Some(encode_structured_detail(&d)))
    }

    /// Build a 403 Forbidden with a structured code.
    pub fn forbidden(code: &'static str, detail: impl Into<String>) -> Self {
        ApiError::Forbidden(Some(encode_structured_detail(
            &ErrorDetail::new().code(code).detail(detail),
        )))
    }

    /// Build a 403 Forbidden carrying a structured `code`, `field`, and
    /// human-readable `detail`. Used by the hosted-mode CSRF rejection path
    /// (W7) so the response carries the canonical 5-key envelope with the
    /// offending header surfaced as `field`.
    pub fn forbidden_with_field(
        code: &'static str,
        field: &str,
        detail: impl Into<String>,
    ) -> Self {
        ApiError::Forbidden(Some(encode_structured_detail(
            &ErrorDetail::new().code(code).field(field).detail(detail),
        )))
    }

    /// Build a 401 Unauthorized with a structured code carried via a sentinel
    /// payload on `BadRequest`. We keep a separate route through the response
    /// builder so the status remains 401 while the structured `code` (e.g.
    /// `INVALID_HMAC`) reaches the client.
    pub fn unauthorized(code: &'static str, detail: impl Into<String>) -> Self {
        // Re-use Forbidden as the carrier? No, we want 401. Use a dedicated
        // sentinel that the response builder recognises.
        let payload = encode_structured_detail(&ErrorDetail::new().code(code).detail(detail));
        // Stash the encoded detail into a BadRequest variant tagged with a
        // status override prefix. The response builder pops the prefix and
        // emits 401.
        ApiError::BadRequest(Some(format!("__STATUS:401__{}", payload)))
    }

    /// Build a 410 Gone with a structured code.
    pub fn gone(code: &'static str, detail: impl Into<String>) -> Self {
        ApiError::Gone(Some(encode_structured_detail(
            &ErrorDetail::new().code(code).detail(detail),
        )))
    }

    /// Build a 409 Conflict with a structured code.
    pub fn conflict(code: &'static str, detail: impl Into<String>) -> Self {
        ApiError::Conflict(Some(encode_structured_detail(
            &ErrorDetail::new().code(code).detail(detail),
        )))
    }

    /// Build a 503 ServiceUnavailable with a structured code.
    pub fn service_unavailable(code: &'static str, detail: impl Into<String>) -> Self {
        ApiError::ServiceUnavailable(Some(encode_structured_detail(
            &ErrorDetail::new().code(code).detail(detail),
        )))
    }
}

impl ApiError {
    /// Extract structured detail (encoded by the `bad_request_with`-family
    /// constructors) from an `Option<String>` payload. Returns the optional
    /// status override (used to surface 401 from the unauthorized constructor)
    /// and the `ErrorDetail`.
    fn extract_payload(p: &Option<String>) -> (Option<u16>, Option<ErrorDetail>) {
        let Some(raw) = p.as_deref() else {
            return (None, None);
        };
        // Strip an optional `__STATUS:NNN__` prefix used by `unauthorized()`
        // to override the variant's default status code.
        let (status_override, rest) = if let Some(stripped) = raw.strip_prefix("__STATUS:") {
            if let Some((n, after)) = stripped.split_once("__") {
                if let Ok(s) = n.parse::<u16>() {
                    (Some(s), after)
                } else {
                    (None, raw)
                }
            } else {
                (None, raw)
            }
        } else {
            (None, raw)
        };
        match decode_structured_detail(rest) {
            Some(d) => (status_override, Some(d)),
            None => (status_override, Some(ErrorDetail::from(rest.to_string()))),
        }
    }

    /// Converts this error into an HTTP [`Response`] with the appropriate status
    /// code, JSON body, anti-caching headers, and audit logging.
    pub fn to_response(self) -> Result<Response, WorkerError> {
        let (mut status, default_code, message) = match &self {
            ApiError::BadRequest(_) => (400, "BAD_REQUEST", "Invalid request"),
            ApiError::NotFound => (404, "NOT_FOUND", "Not found"),
            ApiError::Conflict(_) => (409, "CONFLICT", "Request conflict"),
            ApiError::UnsupportedMediaType => (
                415,
                "UNSUPPORTED_MEDIA_TYPE",
                "Content-Type must be application/json",
            ),
            ApiError::Gone(_) => (410, "GONE", "Resource no longer available"),
            ApiError::VerificationFailed => (400, "VERIFICATION_FAILED", "Verification failed"),
            ApiError::InvalidProof => (400, "INVALID_PROOF", "Invalid proof"),
            ApiError::Unauthorized => (401, "UNAUTHORIZED", "Authentication required"),
            ApiError::Forbidden(_) => (403, "FORBIDDEN", "Access denied"),
            ApiError::PayloadTooLarge(_) => (413, "PAYLOAD_TOO_LARGE", "Request too large"),
            ApiError::TooManyRequests(_) => (429, "TOO_MANY_REQUESTS", "Rate limit exceeded"),
            ApiError::PaymentRequired(_) => (402, "PAYMENT_REQUIRED", "Insufficient credits"),
            ApiError::ServiceUnavailable(_) => (
                503,
                "SERVICE_UNAVAILABLE",
                "Service temporarily unavailable",
            ),
            ApiError::Internal(_) => (500, "INTERNAL_ERROR", "Internal server error"),
        };

        // Pull structured detail out of the (sentinel-encoded) payload where
        // present so the diagnostic `code`/`field`/`detail` reach the client.
        let (status_override, detail) = match &self {
            ApiError::BadRequest(d)
            | ApiError::Conflict(d)
            | ApiError::Gone(d)
            | ApiError::Forbidden(d)
            | ApiError::PayloadTooLarge(d)
            | ApiError::TooManyRequests(d)
            | ApiError::PaymentRequired(d)
            | ApiError::ServiceUnavailable(d) => Self::extract_payload(d),
            _ => (None, None),
        };

        if let Some(s) = status_override {
            status = s;
        }

        let (final_code, field, detail_msg) = match detail {
            Some(d) => (
                d.code.unwrap_or_else(|| default_code.to_string()),
                d.field,
                d.detail,
            ),
            None => (default_code.to_string(), None, None),
        };

        let request_id = uuid::Uuid::new_v4().to_string();

        let body = ErrorBody {
            error: message.to_string(),
            code: Some(final_code.clone()),
            field,
            detail: detail_msg,
            request_id: request_id.clone(),
        };
        let _error_code = final_code.as_str();

        if matches!(self, ApiError::Internal(_)) {
            // SECURITY: Log with Display format, not Debug, to avoid leaking internal details
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "[Error] Internal error (request_id={}): {}",
                request_id,
                self
            );
        }

        // SECURITY: Log security-relevant errors for audit trail (ASVS V7.2.1)
        if self.is_security_relevant() {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "{{\"audit\":true,\"event\":\"security_error_response\",\"severity\":\"warning\",\"error_code\":\"{}\",\"http_status\":{},\"request_id\":\"{}\"}}",
                _error_code,
                status,
                request_id
            );
        }

        let mut response = Response::from_json(&body)?.with_status(status);

        // SECURITY: ASVS V4.1.1 - Add explicit charset to Content-Type
        response
            .headers_mut()
            .set("Content-Type", "application/json; charset=utf-8")?;

        // SECURITY: ASVS V14.2.5 - Web cache deception prevention
        // Set strong anti-caching headers on ALL error responses to prevent
        // sensitive data exposure via cache deception attacks (e.g., /api/secret.css)
        // These headers ensure that error responses are never cached by any intermediary
        response.headers_mut().set(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private",
        )?;
        response.headers_mut().set("Pragma", "no-cache")?;
        response.headers_mut().set("Expires", "0")?;

        // VA-ROOT-004: Add Clear-Site-Data header for authentication/authorisation
        // failures. Covers the plain `ApiError::Unauthorized` variant, the
        // `ApiError::Forbidden` variant, AND the `unauthorized()` constructor
        // which builds `BadRequest` with a `__STATUS:401__` override (caught by
        // the `status == 401` arm).
        if matches!(self, ApiError::Unauthorized | ApiError::Forbidden(_)) || status == 401 {
            response.headers_mut().set("Clear-Site-Data", r#""*""#)?;
        }

        Ok(response)
    }

    /// Returns `true` for error variants that warrant security audit logging.
    pub fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            ApiError::Unauthorized
                | ApiError::Forbidden(_)
                | ApiError::VerificationFailed
                | ApiError::InvalidProof
        )
    }

    /// Map a `worker::Error::RustError` Display string back to the `(status, code)`
    /// pair used by [`ApiError::to_response`].
    ///
    /// SECURITY: This recovers the originally-intended HTTP status when an
    /// `ApiError` has been propagated through `?` and converted via the
    /// `From<ApiError> for worker::Error` impl, which loses typed information.
    /// Without this, the dispatcher fallback turns every `ApiError` into a
    /// generic 500, masking 400/401/403/404/etc. with `INTERNAL_ERROR`.
    ///
    /// Returns `None` for messages that do not match a known [`ApiError`]
    /// Display string. Callers should treat `None` as a true internal error
    /// and respond with 500.
    pub fn status_for_display_str(s: &str) -> Option<(u16, &'static str)> {
        // Strip any payload envelope first so propagated errors round-trip
        // even when they carry a sentinel-encoded structured detail.
        let base = s.split("!!").next().unwrap_or(s);
        match base {
            "bad-request" => Some((400, "BAD_REQUEST")),
            "not-found" => Some((404, "NOT_FOUND")),
            "conflict" => Some((409, "CONFLICT")),
            "gone" => Some((410, "GONE")),
            "verification-failed" => Some((400, "VERIFICATION_FAILED")),
            "invalid-proof" => Some((400, "INVALID_PROOF")),
            "unauthorized" => Some((401, "UNAUTHORIZED")),
            "forbidden" => Some((403, "FORBIDDEN")),
            "payload-too-large" => Some((413, "PAYLOAD_TOO_LARGE")),
            "unsupported-media-type" => Some((415, "UNSUPPORTED_MEDIA_TYPE")),
            "too-many-requests" => Some((429, "TOO_MANY_REQUESTS")),
            "payment-required" => Some((402, "PAYMENT_REQUIRED")),
            "service-unavailable" => Some((503, "SERVICE_UNAVAILABLE")),
            "internal-server-error" => Some((500, "INTERNAL_ERROR")),
            _ => None,
        }
    }

    /// Decode the `<base>!!<payload>` envelope produced by
    /// `From<ApiError> for worker::Error`. Returns the base Display token and
    /// the raw payload string (still in sentinel-encoded form, possibly with
    /// a `__STATUS:NNN__` prefix).
    fn parse_display_envelope(s: &str) -> (&str, Option<String>) {
        if let Some((base, payload)) = s.split_once("!!") {
            (base, Some(payload.to_string()))
        } else {
            (s, None)
        }
    }

    /// Convert a propagated `worker::Error` back into an HTTP [`Response`] with
    /// the correct status code, preserving the typed information that was lost
    /// when `ApiError` was converted via `?` into `worker::Error::RustError`.
    ///
    /// Falls back to a 500 `INTERNAL_ERROR` response when the error message
    /// does not match a known [`ApiError`] Display string.
    pub fn response_from_worker_error(err: &WorkerError) -> Result<Response, WorkerError> {
        let s = err.to_string();
        let (base, payload) = Self::parse_display_envelope(&s);
        match Self::status_for_display_str(base) {
            Some((mut status, default_code)) => {
                // Decode the payload to recover code/field/detail and any
                // status override (used by the `unauthorized()` constructor
                // to surface 401 from a `BadRequest`-shaped propagation).
                let (status_override, detail) = Self::extract_payload(&payload);
                if let Some(s) = status_override {
                    status = s;
                }
                let (final_code, field, detail_msg) = match detail {
                    Some(d) => (
                        d.code.unwrap_or_else(|| default_code.to_string()),
                        d.field,
                        d.detail,
                    ),
                    None => (default_code.to_string(), None, None),
                };
                build_error_response_full(status, &final_code, base, field, detail_msg)
                // (note: this match arm is also used by `to_response` via the
                // shared envelope decoding; see test_each_error_code_round_trip_status)
            }
            None => build_error_response(500, "INTERNAL_ERROR", "Internal server error"),
        }
    }
}

/// Build a JSON error response with anti-caching and security headers.
///
/// Internal helper used by both [`ApiError::to_response`] and
/// [`ApiError::response_from_worker_error`] so the two paths emit identical
/// envelopes (modulo the `request_id`).
fn build_error_response(
    status: u16,
    error_code: &str,
    display_message: &str,
) -> Result<Response, WorkerError> {
    build_error_response_full(status, error_code, display_message, None, None)
}

fn build_error_response_full(
    status: u16,
    error_code: &str,
    display_message: &str,
    field: Option<String>,
    detail: Option<String>,
) -> Result<Response, WorkerError> {
    // Map Display tokens to the same human-readable messages used by `to_response`.
    let message = match display_message {
        "bad-request" => "Invalid request",
        "not-found" => "Not found",
        "conflict" => "Request conflict",
        "gone" => "Resource no longer available",
        "verification-failed" => "Verification failed",
        "invalid-proof" => "Invalid proof",
        "unauthorized" => "Authentication required",
        "forbidden" => "Access denied",
        "payload-too-large" => "Request too large",
        "unsupported-media-type" => "Content-Type must be application/json",
        "too-many-requests" => "Rate limit exceeded",
        "payment-required" => "Insufficient credits",
        "service-unavailable" => "Service temporarily unavailable",
        _ => "Internal server error",
    };

    let request_id = uuid::Uuid::new_v4().to_string();
    let body = ErrorBody {
        error: message.to_string(),
        code: Some(error_code.to_string()),
        field,
        detail,
        request_id: request_id.clone(),
    };

    // Mirror the audit + internal-error logging done by `to_response` so a
    // propagated error produces the same observability signals.
    if status == 500 {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "[Error] Internal error (request_id={}): {}",
            request_id,
            display_message
        );
    }
    if matches!(status, 401 | 403) || matches!(error_code, "VERIFICATION_FAILED" | "INVALID_PROOF")
    {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "{{\"audit\":true,\"event\":\"security_error_response\",\"severity\":\"warning\",\"error_code\":\"{}\",\"http_status\":{},\"request_id\":\"{}\"}}",
            error_code,
            status,
            request_id
        );
    }

    let mut response = Response::from_json(&body)?.with_status(status);
    response
        .headers_mut()
        .set("Content-Type", "application/json; charset=utf-8")?;
    response.headers_mut().set(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, private",
    )?;
    response.headers_mut().set("Pragma", "no-cache")?;
    response.headers_mut().set("Expires", "0")?;
    // VA-ROOT-004: Use wildcard Clear-Site-Data for auth failures.
    if status == 401 || status == 403 {
        response.headers_mut().set("Clear-Site-Data", r#""*""#)?;
    }
    Ok(response)
}

/// Conversion helpers so API errors integrate cleanly with the Workers runtime.
///
/// Encodes the variant payload (which may carry a sentinel-encoded structured
/// detail) into the `RustError` display string using a
/// `<base>!!<payload>` envelope so `response_from_worker_error` can
/// reconstruct status, code, field, and detail when the error has been
/// propagated through `?`. Errors without a payload keep the bare Display
/// string for backwards compatibility with `status_for_display_str` callers.
impl From<ApiError> for worker::Error {
    fn from(err: ApiError) -> Self {
        let base = err.to_string();
        let payload = match &err {
            ApiError::BadRequest(d)
            | ApiError::Conflict(d)
            | ApiError::Gone(d)
            | ApiError::Forbidden(d)
            | ApiError::PayloadTooLarge(d)
            | ApiError::TooManyRequests(d)
            | ApiError::PaymentRequired(d)
            | ApiError::ServiceUnavailable(d) => d.clone(),
            _ => None,
        };
        match payload {
            Some(p) if !p.is_empty() => worker::Error::RustError(format!("{}!!{}", base, p)),
            _ => worker::Error::RustError(base),
        }
    }
}

/// Wraps a Workers runtime error as an internal API error.
impl From<worker::Error> for ApiError {
    fn from(err: worker::Error) -> Self {
        ApiError::Internal(anyhow::anyhow!(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    ERROR VARIANT CONSTRUCTION TESTS                       */
    /* ========================================================================== */

    #[test]
    fn test_bad_request_without_message() {
        let err = ApiError::BadRequest(None);
        assert_eq!(err.to_string(), "bad-request");
    }

    #[test]
    fn test_bad_request_with_message() {
        let err = ApiError::BadRequest(Some("Invalid field".to_string()));
        assert_eq!(err.to_string(), "bad-request");
    }

    #[test]
    fn test_not_found() {
        let err = ApiError::NotFound;
        assert_eq!(err.to_string(), "not-found");
    }

    #[test]
    fn test_conflict_without_message() {
        let err = ApiError::Conflict(None);
        assert_eq!(err.to_string(), "conflict");
    }

    #[test]
    fn test_conflict_with_message() {
        let err = ApiError::Conflict(Some("Duplicate ID".to_string()));
        assert_eq!(err.to_string(), "conflict");
    }

    #[test]
    fn test_gone_without_message() {
        let err = ApiError::Gone(None);
        assert_eq!(err.to_string(), "gone");
    }

    #[test]
    fn test_gone_with_message() {
        let err = ApiError::Gone(Some("Challenge expired".to_string()));
        assert_eq!(err.to_string(), "gone");
    }

    #[test]
    fn test_verification_failed() {
        let err = ApiError::VerificationFailed;
        assert_eq!(err.to_string(), "verification-failed");
    }

    #[test]
    fn test_invalid_proof() {
        let err = ApiError::InvalidProof;
        assert_eq!(err.to_string(), "invalid-proof");
    }

    #[test]
    fn test_unauthorized() {
        let err = ApiError::Unauthorized;
        assert_eq!(err.to_string(), "unauthorized");
    }

    #[test]
    fn test_forbidden_without_message() {
        let err = ApiError::Forbidden(None);
        assert_eq!(err.to_string(), "forbidden");
    }

    #[test]
    fn test_forbidden_with_message() {
        let err = ApiError::Forbidden(Some("Banned origin".to_string()));
        assert_eq!(err.to_string(), "forbidden");
    }

    #[test]
    fn test_payload_too_large_without_message() {
        let err = ApiError::PayloadTooLarge(None);
        assert_eq!(err.to_string(), "payload-too-large");
    }

    #[test]
    fn test_payload_too_large_with_message() {
        let err = ApiError::PayloadTooLarge(Some("Exceeded 10MB".to_string()));
        assert_eq!(err.to_string(), "payload-too-large");
    }

    #[test]
    fn test_unsupported_media_type() {
        let err = ApiError::UnsupportedMediaType;
        assert_eq!(err.to_string(), "unsupported-media-type");
    }

    #[test]
    fn test_internal_from_anyhow() {
        let anyhow_err = anyhow::anyhow!("Database connection failed");
        let err = ApiError::Internal(anyhow_err);
        assert_eq!(err.to_string(), "internal-server-error");
    }

    /* ========================================================================== */
    /*                    is_security_relevant() TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_unauthorized_is_security_relevant() {
        assert!(ApiError::Unauthorized.is_security_relevant());
    }

    #[test]
    fn test_forbidden_is_security_relevant() {
        assert!(ApiError::Forbidden(None).is_security_relevant());
        assert!(ApiError::Forbidden(Some("msg".to_string())).is_security_relevant());
    }

    #[test]
    fn test_verification_failed_is_security_relevant() {
        assert!(ApiError::VerificationFailed.is_security_relevant());
    }

    #[test]
    fn test_invalid_proof_is_security_relevant() {
        assert!(ApiError::InvalidProof.is_security_relevant());
    }

    #[test]
    fn test_bad_request_not_security_relevant() {
        assert!(!ApiError::BadRequest(None).is_security_relevant());
    }

    #[test]
    fn test_not_found_not_security_relevant() {
        assert!(!ApiError::NotFound.is_security_relevant());
    }

    #[test]
    fn test_conflict_not_security_relevant() {
        assert!(!ApiError::Conflict(None).is_security_relevant());
    }

    #[test]
    fn test_gone_not_security_relevant() {
        assert!(!ApiError::Gone(None).is_security_relevant());
    }

    #[test]
    fn test_payload_too_large_not_security_relevant() {
        assert!(!ApiError::PayloadTooLarge(None).is_security_relevant());
    }

    #[test]
    fn test_unsupported_media_type_not_security_relevant() {
        assert!(!ApiError::UnsupportedMediaType.is_security_relevant());
    }

    #[test]
    fn test_internal_not_security_relevant() {
        let err = ApiError::Internal(anyhow::anyhow!("test"));
        assert!(!err.is_security_relevant());
    }

    #[test]
    fn test_service_unavailable_not_security_relevant() {
        assert!(!ApiError::ServiceUnavailable(None).is_security_relevant());
        assert!(!ApiError::ServiceUnavailable(Some("test".to_string())).is_security_relevant());
    }

    #[test]
    fn test_service_unavailable_display() {
        let err = ApiError::ServiceUnavailable(None);
        assert_eq!(err.to_string(), "service-unavailable");
    }

    /* ========================================================================== */
    /*                    CONVERSION TESTS                                       */
    /* ========================================================================== */

    #[test]
    fn test_from_anyhow_error() {
        let anyhow_err = anyhow::anyhow!("Something went wrong");
        let api_err: ApiError = anyhow_err.into();
        assert!(matches!(api_err, ApiError::Internal(_)));
    }

    #[test]
    fn test_api_error_to_worker_error() {
        let api_err = ApiError::BadRequest(None);
        let worker_err: worker::Error = api_err.into();
        assert_eq!(worker_err.to_string(), "bad-request");
    }

    #[test]
    fn test_api_error_debug_format() {
        let err = ApiError::BadRequest(Some("test".to_string()));
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("BadRequest"));
    }

    /* ========================================================================== */
    /*    PG-VAL-001: Structured error code envelope round-trip                  */
    /* ========================================================================== */

    /// `bad_request()` packs `code/field/detail` into the payload, and a
    /// propagation through `?` -> `worker::Error` -> `response_from_worker_error`
    /// recovers them so the dispatcher fallback emits the structured body.
    #[test]
    fn test_bad_request_structured_envelope_round_trips() {
        let err = ApiError::bad_request(
            "ORIGIN_MISSING",
            Some("Origin"),
            "Origin header is required",
        );
        let we: WorkerError = err.into();
        let s = we.to_string();
        // Display token must still parse to the right status.
        assert_eq!(
            ApiError::status_for_display_str(&s),
            Some((400, "BAD_REQUEST"))
        );
        // Envelope must carry the sentinel-encoded structured payload.
        assert!(
            s.contains("ORIGIN_MISSING"),
            "missing code in envelope: {s}"
        );
        assert!(s.contains("Origin"), "missing field in envelope: {s}");
    }

    /// `unauthorized()` constructor uses `__STATUS:401__` to surface 401
    /// from a `BadRequest`-shaped propagation while keeping the structured
    /// `INVALID_HMAC` code visible to clients.
    #[test]
    fn test_unauthorized_structured_envelope_surfaces_401() {
        let err = ApiError::unauthorized("INVALID_HMAC", "HMAC mismatch");
        let we: WorkerError = err.into();
        let s = we.to_string();
        // Base token still parses (the propagation envelope is `bad-request!!__STATUS:401__...`).
        let (base, _payload) = ApiError::parse_display_envelope(&s);
        assert_eq!(base, "bad-request");
        // The `__STATUS:401__` prefix lives inside the payload.
        assert!(s.contains("__STATUS:401__"));
        assert!(s.contains("INVALID_HMAC"));
    }

    /// Each documented error code maps to the correct `(status, code)` pair
    /// after a full propagation round-trip via `From<ApiError> for worker::Error`
    /// and back through `response_from_worker_error`.
    #[test]
    fn test_each_error_code_round_trip_status() {
        let cases: Vec<(ApiError, u16, &str)> = vec![
            (
                ApiError::bad_request("ORIGIN_MISSING", Some("Origin"), "x"),
                400,
                "ORIGIN_MISSING",
            ),
            (
                ApiError::bad_request("BODY_SCHEMA_INVALID", Some("body"), "x"),
                400,
                "BODY_SCHEMA_INVALID",
            ),
            (
                ApiError::bad_request("INVALID_PKCE_VERIFIER", Some("code_verifier"), "x"),
                400,
                "INVALID_PKCE_VERIFIER",
            ),
            (
                ApiError::unauthorized("INVALID_HMAC", "x"),
                401,
                "INVALID_HMAC",
            ),
            (
                ApiError::unauthorized("NONCE_REPLAY", "x"),
                401,
                "NONCE_REPLAY",
            ),
            (
                ApiError::unauthorized("API_KEY_MISSING", "x"),
                401,
                "API_KEY_MISSING",
            ),
            (
                ApiError::forbidden("ORIGIN_NOT_ALLOWED", "x"),
                403,
                "ORIGIN_NOT_ALLOWED",
            ),
            (
                ApiError::forbidden("ORIGIN_DISABLED", "x"),
                403,
                "ORIGIN_DISABLED",
            ),
            (
                ApiError::gone("CHALLENGE_EXPIRED", "x"),
                410,
                "CHALLENGE_EXPIRED",
            ),
            (
                ApiError::conflict("CHALLENGE_ALREADY_REDEEMED", "x"),
                409,
                "CHALLENGE_ALREADY_REDEEMED",
            ),
        ];
        for (err, expected_status, expected_code) in cases {
            let we: WorkerError = err.into();
            let s = we.to_string();
            let (base, payload) = ApiError::parse_display_envelope(&s);
            // Default status per Display token (without override).
            let (default_status, _default_code) =
                ApiError::status_for_display_str(base).unwrap_or((0, ""));

            // Apply the optional __STATUS:NNN__ override embedded by the unauthorized()
            // constructor so we can assert against the final status surfaced to clients.
            let (status_override, detail) = ApiError::extract_payload(&payload);
            let final_status = status_override.unwrap_or(default_status);
            assert_eq!(
                final_status, expected_status,
                "wrong status for code {expected_code}: got {final_status}, want {expected_status} (envelope: {s})"
            );

            let detail = detail.expect("structured detail should round-trip");
            assert_eq!(
                detail.code.as_deref(),
                Some(expected_code),
                "wrong code in envelope: {s}"
            );
        }
    }

    /// PG-VAL-002 regression: malformed PKCE deser produces BODY_SCHEMA_INVALID,
    /// not the previous opaque BAD_REQUEST.
    #[test]
    fn test_malformed_pkce_yields_structured_code() {
        let err = ApiError::bad_request(
            "INVALID_PKCE_CHALLENGE",
            Some("code_challenge"),
            "expected base64url-encoded 32 bytes (43 chars)",
        );
        let we: WorkerError = err.into();
        let s = we.to_string();
        assert!(s.contains("INVALID_PKCE_CHALLENGE"));
        assert!(s.contains("code_challenge"));
    }

    /// HMAC mismatch is 401 (UNAUTHORIZED) with INVALID_HMAC code per docs,
    /// not 400 (BAD_REQUEST). Regression for PG-VAL bug 2.
    #[test]
    fn test_hmac_mismatch_status_is_401() {
        let err = ApiError::unauthorized(
            "INVALID_HMAC",
            "HMAC signature does not match the canonical request",
        );
        let we: WorkerError = err.into();
        let s = we.to_string();
        let (_base, payload) = ApiError::parse_display_envelope(&s);
        let (status_override, detail) = ApiError::extract_payload(&payload);
        assert_eq!(status_override, Some(401), "HMAC mismatch must surface 401");
        assert_eq!(
            detail.and_then(|d| d.code).as_deref(),
            Some("INVALID_HMAC"),
            "HMAC mismatch must carry INVALID_HMAC code"
        );
    }

    /// PG-VAL-003 (reverse): propagated Internal errors (KV failures, etc.)
    /// must NOT be mistaken for a structured ApiError just because their
    /// message happens to contain a pipe character.
    #[test]
    fn test_opaque_internal_error_with_pipe_still_500() {
        let opaque = WorkerError::RustError("KV failure: foo|bar baz".to_string());
        let s = opaque.to_string();
        let (base, _) = ApiError::parse_display_envelope(&s);
        // `KV failure: foo` is not a known ApiError Display token.
        assert_eq!(ApiError::status_for_display_str(base), None);
    }

    /* ========================================================================== */
    /*           status_for_display_str(): propagated-error recovery             */
    /* ========================================================================== */

    #[test]
    fn test_status_for_display_str_forbidden_maps_to_403() {
        // The exact case the user reported: a propagated `ApiError::Forbidden`
        // turned into `WorkerError::RustError("forbidden")` by `?`.
        assert_eq!(
            ApiError::status_for_display_str("forbidden"),
            Some((403, "FORBIDDEN"))
        );
    }

    #[test]
    fn test_status_for_display_str_bad_request_maps_to_400() {
        assert_eq!(
            ApiError::status_for_display_str("bad-request"),
            Some((400, "BAD_REQUEST"))
        );
    }

    #[test]
    fn test_status_for_display_str_unauthorized_maps_to_401() {
        assert_eq!(
            ApiError::status_for_display_str("unauthorized"),
            Some((401, "UNAUTHORIZED"))
        );
    }

    #[test]
    fn test_status_for_display_str_unknown_returns_none() {
        // Random worker errors must NOT be silently treated as a known ApiError.
        assert_eq!(ApiError::status_for_display_str("KV get failed"), None);
        assert_eq!(ApiError::status_for_display_str(""), None);
    }

    #[test]
    fn test_status_for_display_str_round_trip_all_variants() {
        // Every ApiError variant's Display string must round-trip back to a
        // matching status code. This guards against drift between Display and
        // status_for_display_str when new variants are added.
        let cases = [
            (ApiError::BadRequest(None), 400),
            (ApiError::NotFound, 404),
            (ApiError::Conflict(None), 409),
            (ApiError::Gone(None), 410),
            (ApiError::VerificationFailed, 400),
            (ApiError::InvalidProof, 400),
            (ApiError::Unauthorized, 401),
            (ApiError::Forbidden(None), 403),
            (ApiError::PayloadTooLarge(None), 413),
            (ApiError::UnsupportedMediaType, 415),
            (ApiError::TooManyRequests(None), 429),
            (ApiError::PaymentRequired(None), 402),
            (ApiError::ServiceUnavailable(None), 503),
            (ApiError::Internal(anyhow::anyhow!("x")), 500),
        ];
        for (err, expected_status) in cases {
            let display = err.to_string();
            let mapped = ApiError::status_for_display_str(&display);
            assert!(mapped.is_some(), "missing mapping for {}", display);
            if let Some((status, _code)) = mapped {
                assert_eq!(
                    status, expected_status,
                    "Display='{}' produced wrong status",
                    display
                );
            }
        }
    }

    /* ========================================================================== */
    /*    REGRESSION: Mismatched-Origin returns 403 (not 500), bad body 400      */
    /* ========================================================================== */

    /// Bug-2 regression: a Forbidden error propagated through `?` from the
    /// challenge handler MUST round-trip to 403, not 500 INTERNAL_ERROR.
    ///
    /// Reproduces the user-reported tail-log case verbatim:
    ///   `[/v1/challenge] Handler error: RustError("forbidden")`
    /// Previously returned HTTP 500. After the fix, the dispatcher's
    /// `handler_error_to_response` calls `status_for_display_str("forbidden")`
    /// and returns 403.
    #[test]
    fn test_regression_mismatched_origin_propagates_as_403() {
        // The exact worker error shape the user pasted in the bug report.
        let propagated = WorkerError::RustError("forbidden".to_string());
        let s = propagated.to_string();
        let mapped = ApiError::status_for_display_str(&s);
        assert_eq!(
            mapped,
            Some((403, "FORBIDDEN")),
            "mismatched-origin must yield 403, got {:?}",
            mapped
        );
    }

    /// Bug-2 regression: a malformed body produces a `BadRequest` which, when
    /// propagated through `?`, must round-trip to 400, not 500.
    #[test]
    fn test_regression_malformed_body_propagates_as_400() {
        let propagated: WorkerError = ApiError::BadRequest(Some("Invalid JSON".into())).into();
        let s = propagated.to_string();
        let mapped = ApiError::status_for_display_str(&s);
        assert_eq!(
            mapped,
            Some((400, "BAD_REQUEST")),
            "malformed body must yield 400, got {:?}",
            mapped
        );
    }

    /// Counter-test: opaque worker errors (KV failures, JS runtime panics)
    /// must still map to 500. The fallback is unchanged for genuinely
    /// internal failures.
    #[test]
    fn test_regression_opaque_worker_error_still_500() {
        let opaque = WorkerError::RustError("KV get failed: connection reset".to_string());
        let s = opaque.to_string();
        // None means the dispatcher will fall back to 500 INTERNAL_ERROR,
        // which is the correct behaviour for an unrecognised internal error.
        assert_eq!(ApiError::status_for_display_str(&s), None);
    }

    /// Hosted-mode regression: the original bug was that
    /// `/v1/hosted/challenge` and friends explicitly constructed
    /// `WorkerError::RustError("Invalid request body".into())` on bad JSON
    /// instead of going through `ApiError`. The Display string of that
    /// `WorkerError` is the bare message ("Invalid request body"), which
    /// `status_for_display_str` correctly returns `None` for, so the
    /// dispatcher fell back to 500. After the fix the hosted handlers wrap
    /// the parse error in `ApiError::BadRequest`, and the Display string is
    /// `"bad-request"`, which round-trips to 400. Both branches are asserted
    /// here so future drift between the two patterns is caught immediately.
    #[test]
    fn test_regression_hosted_invalid_body_string_unmapped() {
        // OLD pattern (pre-fix): plain RustError("Invalid request body").
        // Confirms WHY the bug existed: the message doesn't round-trip.
        let pre_fix = WorkerError::RustError("Invalid request body".to_string());
        assert_eq!(
            ApiError::status_for_display_str(&pre_fix.to_string()),
            None,
            "RustError(\"Invalid request body\") must NOT silently look like a known ApiError"
        );

        // NEW pattern (post-fix): WorkerError::from(ApiError::BadRequest(...)).
        let post_fix: WorkerError =
            ApiError::BadRequest(Some("Invalid request body".into())).into();
        assert_eq!(
            ApiError::status_for_display_str(&post_fix.to_string()),
            Some((400, "BAD_REQUEST")),
            "ApiError::BadRequest must round-trip to 400 BAD_REQUEST"
        );
    }

    /// Hosted-mode regression: service-unavailable failures (KV bind, nonce DO
    /// store, secure_random) must round-trip to 503, not 500, after the fix.
    #[test]
    fn test_regression_hosted_service_unavailable_round_trips_to_503() {
        let propagated: WorkerError = ApiError::ServiceUnavailable(None).into();
        assert_eq!(
            ApiError::status_for_display_str(&propagated.to_string()),
            Some((503, "SERVICE_UNAVAILABLE")),
            "ServiceUnavailable must round-trip to 503"
        );
    }

    /* ========================================================================== */
    /*                    ERROR BODY SERIALISATION TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_error_body_serialisation_with_code() -> Result<(), Box<dyn std::error::Error>> {
        let body = ErrorBody {
            error: "Test error".to_string(),
            code: Some("TEST_CODE".to_string()),
            field: None,
            detail: None,
            request_id: "test-req-id".to_string(),
        };
        let json = serde_json::to_string(&body)?;
        assert!(json.contains("Test error"));
        assert!(json.contains("TEST_CODE"));
        assert!(json.contains("test-req-id"));
        Ok(())
    }

    #[test]
    fn test_error_body_serialisation_without_code() -> Result<(), Box<dyn std::error::Error>> {
        let body = ErrorBody {
            error: "Test error".to_string(),
            code: None,
            field: None,
            detail: None,
            request_id: "test-req-id".to_string(),
        };
        let json = serde_json::to_string(&body)?;
        assert!(json.contains("Test error"));
        assert!(!json.contains("code"));
        assert!(json.contains("request_id"));
        Ok(())
    }

    /* ========================================================================== */
    /*    W7-P1: Canonical 5-key envelope (error, code, field, detail,          */
    /*    request_id). Hosted-mode CSRF rejection and bare NotFound previously  */
    /*    emitted 2-key and 3-key bodies; the serde change drops                */
    /*    skip_serializing_if on field/detail so all error responses share the  */
    /*    same shape.                                                           */
    /* ========================================================================== */

    /// Bare `NotFound` MUST emit the canonical 5-key envelope with explicit
    /// `field: null` and `detail: null` rather than dropping them.
    #[test]
    fn test_error_body_not_found_emits_five_keys() -> Result<(), Box<dyn std::error::Error>> {
        let body = ErrorBody {
            error: "Not found".to_string(),
            code: Some("NOT_FOUND".to_string()),
            field: None,
            detail: None,
            request_id: "test-req-id".to_string(),
        };
        let json = serde_json::to_string(&body)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        let obj = parsed.as_object().ok_or("expected object")?;
        assert!(obj.contains_key("error"), "missing key error: {json}");
        assert!(obj.contains_key("code"), "missing key code: {json}");
        assert!(obj.contains_key("field"), "missing key field: {json}");
        assert!(obj.contains_key("detail"), "missing key detail: {json}");
        assert!(
            obj.contains_key("request_id"),
            "missing key request_id: {json}"
        );
        assert!(obj["field"].is_null(), "field must be null when unset");
        assert!(obj["detail"].is_null(), "detail must be null when unset");
        assert_eq!(obj.len(), 5, "must be exactly 5 keys: {json}");
        Ok(())
    }

    /// CSRF rejection wraps via `forbidden_with_field`; the produced envelope
    /// MUST carry all 5 canonical keys with `field` populated.
    #[test]
    fn test_forbidden_with_field_constructor_carries_field(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::forbidden_with_field(
            "CSRF_INVALID",
            "X-CSRF-Token",
            "Session-bound CSRF token required",
        );
        // Round-trip through the WorkerError envelope so we exercise the path
        // used by `?` propagation.
        let we: WorkerError = err.into();
        let s = we.to_string();
        assert!(
            s.starts_with("forbidden!!"),
            "expected forbidden token: {s}"
        );
        assert!(s.contains("CSRF_INVALID"), "missing code: {s}");
        assert!(s.contains("X-CSRF-Token"), "missing field: {s}");
        assert!(
            s.contains("Session-bound CSRF token required"),
            "missing detail: {s}"
        );
        Ok(())
    }

    /// ORIGIN_MISSING must round-trip to a 400 with the structured payload
    /// intact. This guards the W7-B3 fix: short-circuiting Origin extraction
    /// at the top of `create_challenge` MUST still surface the full envelope
    /// to the client (no plain-string fallback).
    #[test]
    fn test_origin_missing_envelope_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::bad_request(
            "ORIGIN_MISSING",
            Some("Origin"),
            "Origin header is required",
        );
        let we: WorkerError = err.into();
        let s = we.to_string();
        assert_eq!(
            ApiError::status_for_display_str(&s),
            Some((400, "BAD_REQUEST"))
        );
        assert!(s.contains("ORIGIN_MISSING"));
        assert!(s.contains("Origin"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    STATUS CODE MAPPING TESTS                              */
    /* ========================================================================== */

    // Note: These tests verify the expected status codes for each error type
    // Full to_response() tests require the worker runtime

    #[test]
    fn test_bad_request_maps_to_400() {
        // BadRequest should map to status 400
        let err = ApiError::BadRequest(None);
        assert_eq!(err.to_string(), "bad-request");
    }

    #[test]
    fn test_unauthorized_maps_to_401() {
        // Unauthorized should map to status 401
        let err = ApiError::Unauthorized;
        assert_eq!(err.to_string(), "unauthorized");
    }

    #[test]
    fn test_forbidden_maps_to_403() {
        // Forbidden should map to status 403
        let err = ApiError::Forbidden(None);
        assert_eq!(err.to_string(), "forbidden");
    }

    #[test]
    fn test_not_found_maps_to_404() {
        // NotFound should map to status 404
        let err = ApiError::NotFound;
        assert_eq!(err.to_string(), "not-found");
    }

    #[test]
    fn test_conflict_maps_to_409() {
        // Conflict should map to status 409
        let err = ApiError::Conflict(None);
        assert_eq!(err.to_string(), "conflict");
    }

    #[test]
    fn test_gone_maps_to_410() {
        // Gone should map to status 410
        let err = ApiError::Gone(None);
        assert_eq!(err.to_string(), "gone");
    }

    #[test]
    fn test_payload_too_large_maps_to_413() {
        // PayloadTooLarge should map to status 413
        let err = ApiError::PayloadTooLarge(None);
        assert_eq!(err.to_string(), "payload-too-large");
    }

    #[test]
    fn test_unsupported_media_type_maps_to_415() {
        // UnsupportedMediaType should map to status 415
        let err = ApiError::UnsupportedMediaType;
        assert_eq!(err.to_string(), "unsupported-media-type");
    }

    #[test]
    fn test_internal_maps_to_500() {
        // Internal should map to status 500
        let err = ApiError::Internal(anyhow::anyhow!("test"));
        assert_eq!(err.to_string(), "internal-server-error");
    }

    /* ========================================================================== */
    /*                    ERROR MESSAGE TESTS                                    */
    /* ========================================================================== */

    #[test]
    fn test_optional_message_preserved() {
        let msg = "Custom error details";
        let err = ApiError::BadRequest(Some(msg.to_string()));
        assert!(
            matches!(&err, ApiError::BadRequest(Some(inner)) if inner == msg),
            "Expected BadRequest with message"
        );
    }

    #[test]
    fn test_empty_optional_message() {
        let err = ApiError::Forbidden(Some(String::new()));
        assert!(
            matches!(&err, ApiError::Forbidden(Some(inner)) if inner.is_empty()),
            "Expected Forbidden with empty message"
        );
    }

    #[test]
    fn test_long_error_message() {
        let long_msg = "x".repeat(10000);
        let err = ApiError::Conflict(Some(long_msg.clone()));
        assert!(
            matches!(&err, ApiError::Conflict(Some(inner)) if inner.len() == 10000),
            "Expected Conflict with long message"
        );
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    /* ========================================================================== */
    /*                    ErrorDetail BUILDER TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_error_detail_new_all_none() {
        let d = ErrorDetail::new();
        assert_eq!(d.code, None);
        assert_eq!(d.field, None);
        assert_eq!(d.detail, None);
    }

    #[test]
    fn test_error_detail_builder_chain() {
        let d = ErrorDetail::new()
            .code("ORIGIN_MISSING")
            .field("Origin")
            .detail("Origin header is required");
        assert_eq!(d.code.as_deref(), Some("ORIGIN_MISSING"));
        assert_eq!(d.field.as_deref(), Some("Origin"));
        assert_eq!(d.detail.as_deref(), Some("Origin header is required"));
    }

    #[test]
    fn test_error_detail_default() {
        let d = ErrorDetail::default();
        assert_eq!(d.code, None);
        assert_eq!(d.field, None);
        assert_eq!(d.detail, None);
    }

    #[test]
    fn test_error_detail_from_string() {
        let d = ErrorDetail::from("test message".to_string());
        assert_eq!(d.code, None);
        assert_eq!(d.field, None);
        assert_eq!(d.detail, Some("test message".to_string()));
    }

    #[test]
    fn test_error_detail_from_str() {
        let d = ErrorDetail::from("test");
        assert_eq!(d.code, None);
        assert_eq!(d.field, None);
        assert_eq!(d.detail, Some("test".to_string()));
    }

    #[test]
    fn test_error_detail_from_empty_string() {
        let d = ErrorDetail::from("".to_string());
        assert_eq!(d.detail, Some(String::new()));
    }

    #[test]
    fn test_error_detail_eq() {
        let a = ErrorDetail::new().code("A");
        let b = ErrorDetail::new().code("A");
        assert_eq!(a, b);
    }

    #[test]
    fn test_error_detail_ne() {
        let a = ErrorDetail::new().code("A");
        let b = ErrorDetail::new().code("B");
        assert_ne!(a, b);
    }

    /* ========================================================================== */
    /*                    encode/decode_structured_detail TESTS                  */
    /* ========================================================================== */

    #[test]
    fn test_encode_decode_full() -> Result<(), Box<dyn std::error::Error>> {
        let d = ErrorDetail::new()
            .code("ORIGIN_MISSING")
            .field("Origin")
            .detail("header required");
        let encoded = encode_structured_detail(&d);
        let decoded = decode_structured_detail(&encoded).ok_or("decode failed")?;
        assert_eq!(decoded.code.as_deref(), Some("ORIGIN_MISSING"));
        assert_eq!(decoded.field.as_deref(), Some("Origin"));
        assert_eq!(decoded.detail.as_deref(), Some("header required"));
        Ok(())
    }

    #[test]
    fn test_encode_decode_code_only() -> Result<(), Box<dyn std::error::Error>> {
        let d = ErrorDetail::new().code("INVALID_HMAC");
        let encoded = encode_structured_detail(&d);
        let decoded = decode_structured_detail(&encoded).ok_or("decode failed")?;
        assert_eq!(decoded.code.as_deref(), Some("INVALID_HMAC"));
        assert_eq!(decoded.field, None);
        assert_eq!(decoded.detail, None);
        Ok(())
    }

    #[test]
    fn test_encode_decode_empty() -> Result<(), Box<dyn std::error::Error>> {
        let d = ErrorDetail::new();
        let encoded = encode_structured_detail(&d);
        let decoded = decode_structured_detail(&encoded).ok_or("decode failed")?;
        assert_eq!(decoded.code, None);
        assert_eq!(decoded.field, None);
        assert_eq!(decoded.detail, None);
        Ok(())
    }

    #[test]
    fn test_decode_non_sentinel_returns_none() {
        assert!(decode_structured_detail("just a plain message").is_none());
    }

    #[test]
    fn test_decode_empty_returns_none() {
        assert!(decode_structured_detail("").is_none());
    }

    #[test]
    fn test_encode_pipes_in_field_replaced() -> Result<(), Box<dyn std::error::Error>> {
        let d = ErrorDetail {
            code: Some("CODE".to_string()),
            field: Some("a|b".to_string()),
            detail: Some("c|d".to_string()),
        };
        let encoded = encode_structured_detail(&d);
        // Pipes in field/detail are replaced with slashes
        let decoded = decode_structured_detail(&encoded).ok_or("decode failed")?;
        assert_eq!(decoded.field.as_deref(), Some("a/b"));
        assert_eq!(decoded.detail.as_deref(), Some("c/d"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    extract_payload TESTS                                  */
    /* ========================================================================== */

    #[test]
    fn test_extract_payload_none() {
        let (status, detail) = ApiError::extract_payload(&None);
        assert_eq!(status, None);
        assert!(detail.is_none());
    }

    #[test]
    fn test_extract_payload_plain_string() -> Result<(), Box<dyn std::error::Error>> {
        let payload = Some("plain error message".to_string());
        let (status, detail) = ApiError::extract_payload(&payload);
        assert_eq!(status, None);
        let d = detail.ok_or("expected detail")?;
        // Plain strings are wrapped as ErrorDetail with detail only
        assert_eq!(d.detail.as_deref(), Some("plain error message"));
        assert_eq!(d.code, None);
        assert_eq!(d.field, None);
        Ok(())
    }

    #[test]
    fn test_extract_payload_with_status_override() -> Result<(), Box<dyn std::error::Error>> {
        let inner =
            encode_structured_detail(&ErrorDetail::new().code("INVALID_HMAC").detail("mismatch"));
        let payload = Some(format!("__STATUS:401__{}", inner));
        let (status, detail) = ApiError::extract_payload(&payload);
        assert_eq!(status, Some(401));
        let d = detail.ok_or("expected detail")?;
        assert_eq!(d.code.as_deref(), Some("INVALID_HMAC"));
        Ok(())
    }

    #[test]
    fn test_extract_payload_malformed_status_prefix() {
        let payload = Some("__STATUS:abc__something".to_string());
        let (status, _detail) = ApiError::extract_payload(&payload);
        // Non-numeric status parse fails, so no override
        assert_eq!(status, None);
    }

    /* ========================================================================== */
    /*                    parse_display_envelope TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_parse_display_envelope_with_payload() {
        let (base, payload) = ApiError::parse_display_envelope("bad-request!!some payload");
        assert_eq!(base, "bad-request");
        assert_eq!(payload.as_deref(), Some("some payload"));
    }

    #[test]
    fn test_parse_display_envelope_no_payload() {
        let (base, payload) = ApiError::parse_display_envelope("not-found");
        assert_eq!(base, "not-found");
        assert!(payload.is_none());
    }

    #[test]
    fn test_parse_display_envelope_empty() {
        let (base, payload) = ApiError::parse_display_envelope("");
        assert_eq!(base, "");
        assert!(payload.is_none());
    }

    #[test]
    fn test_parse_display_envelope_multiple_bangs() {
        let (base, payload) = ApiError::parse_display_envelope("bad-request!!a!!b!!c");
        assert_eq!(base, "bad-request");
        assert_eq!(payload.as_deref(), Some("a!!b!!c"));
    }

    /* ========================================================================== */
    /*                    Structured constructor TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_bad_request_constructor_no_field() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::bad_request("BODY_SCHEMA_INVALID", None, "bad JSON");
        let payload = match &err {
            ApiError::BadRequest(Some(p)) => p.clone(),
            _ => return Err("expected BadRequest variant".into()),
        };
        let decoded = decode_structured_detail(&payload).ok_or("decode failed")?;
        assert_eq!(decoded.code.as_deref(), Some("BODY_SCHEMA_INVALID"));
        assert_eq!(decoded.field, None);
        assert_eq!(decoded.detail.as_deref(), Some("bad JSON"));
        Ok(())
    }

    #[test]
    fn test_forbidden_constructor() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::forbidden("ORIGIN_NOT_ALLOWED", "origin disallowed");
        let payload = match &err {
            ApiError::Forbidden(Some(p)) => p.clone(),
            _ => return Err("expected Forbidden variant".into()),
        };
        let decoded = decode_structured_detail(&payload).ok_or("decode failed")?;
        assert_eq!(decoded.code.as_deref(), Some("ORIGIN_NOT_ALLOWED"));
        assert_eq!(decoded.detail.as_deref(), Some("origin disallowed"));
        Ok(())
    }

    #[test]
    fn test_gone_constructor() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::gone("CHALLENGE_EXPIRED", "challenge TTL exceeded");
        let payload = match &err {
            ApiError::Gone(Some(p)) => p.clone(),
            _ => return Err("expected Gone variant".into()),
        };
        let decoded = decode_structured_detail(&payload).ok_or("decode failed")?;
        assert_eq!(decoded.code.as_deref(), Some("CHALLENGE_EXPIRED"));
        Ok(())
    }

    #[test]
    fn test_conflict_constructor() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::conflict("CHALLENGE_ALREADY_REDEEMED", "already redeemed");
        let payload = match &err {
            ApiError::Conflict(Some(p)) => p.clone(),
            _ => return Err("expected Conflict variant".into()),
        };
        let decoded = decode_structured_detail(&payload).ok_or("decode failed")?;
        assert_eq!(decoded.code.as_deref(), Some("CHALLENGE_ALREADY_REDEEMED"));
        Ok(())
    }

    #[test]
    fn test_service_unavailable_constructor() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::service_unavailable("KV_BIND_FAILED", "KV namespace not found");
        let payload = match &err {
            ApiError::ServiceUnavailable(Some(p)) => p.clone(),
            _ => return Err("expected ServiceUnavailable variant".into()),
        };
        let decoded = decode_structured_detail(&payload).ok_or("decode failed")?;
        assert_eq!(decoded.code.as_deref(), Some("KV_BIND_FAILED"));
        assert_eq!(decoded.detail.as_deref(), Some("KV namespace not found"));
        Ok(())
    }

    #[test]
    fn test_unauthorized_constructor_status_override() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::unauthorized("API_KEY_MISSING", "no key");
        let payload = match &err {
            ApiError::BadRequest(Some(p)) => p.clone(),
            _ => return Err("expected BadRequest variant with status override".into()),
        };
        assert!(payload.contains("__STATUS:401__"));
        assert!(payload.contains("API_KEY_MISSING"));
        Ok(())
    }

    #[test]
    fn test_forbidden_with_field_constructor() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::forbidden_with_field("CSRF_INVALID", "X-CSRF-Token", "token required");
        let payload = match &err {
            ApiError::Forbidden(Some(p)) => p.clone(),
            _ => return Err("expected Forbidden variant".into()),
        };
        let decoded = decode_structured_detail(&payload).ok_or("decode failed")?;
        assert_eq!(decoded.code.as_deref(), Some("CSRF_INVALID"));
        assert_eq!(decoded.field.as_deref(), Some("X-CSRF-Token"));
        assert_eq!(decoded.detail.as_deref(), Some("token required"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    MISSING Display TESTS                                  */
    /* ========================================================================== */

    #[test]
    fn test_too_many_requests_display() {
        let err = ApiError::TooManyRequests(None);
        assert_eq!(err.to_string(), "too-many-requests");
    }

    #[test]
    fn test_too_many_requests_with_message_display() {
        let err = ApiError::TooManyRequests(Some("slow down".to_string()));
        assert_eq!(err.to_string(), "too-many-requests");
    }

    #[test]
    fn test_payment_required_display() {
        let err = ApiError::PaymentRequired(None);
        assert_eq!(err.to_string(), "payment-required");
    }

    #[test]
    fn test_payment_required_with_message_display() {
        let err = ApiError::PaymentRequired(Some("no credits".to_string()));
        assert_eq!(err.to_string(), "payment-required");
    }

    #[test]
    fn test_too_many_requests_not_security_relevant() {
        assert!(!ApiError::TooManyRequests(None).is_security_relevant());
    }

    #[test]
    fn test_payment_required_not_security_relevant() {
        assert!(!ApiError::PaymentRequired(None).is_security_relevant());
    }

    /* ========================================================================== */
    /*                    From<worker::Error> for ApiError TESTS                 */
    /* ========================================================================== */

    #[test]
    fn test_worker_error_to_api_error() {
        let we = worker::Error::RustError("KV unavailable".to_string());
        let api_err: ApiError = we.into();
        assert!(matches!(api_err, ApiError::Internal(_)));
    }

    /* ========================================================================== */
    /*                    ApiError -> worker::Error round-trip TESTS             */
    /* ========================================================================== */

    #[test]
    fn test_to_worker_error_none_payload() {
        let we: worker::Error = ApiError::NotFound.into();
        assert_eq!(we.to_string(), "not-found");
    }

    #[test]
    fn test_to_worker_error_some_payload() {
        let we: worker::Error = ApiError::Conflict(Some("dup".to_string())).into();
        let s = we.to_string();
        assert!(s.starts_with("conflict!!"));
        assert!(s.contains("dup"));
    }

    #[test]
    fn test_to_worker_error_empty_payload_no_envelope() {
        let we: worker::Error = ApiError::BadRequest(Some(String::new())).into();
        // Empty payload should NOT produce a `!!` envelope
        assert_eq!(we.to_string(), "bad-request");
    }

    #[test]
    fn test_to_worker_error_verification_failed_no_payload() {
        let we: worker::Error = ApiError::VerificationFailed.into();
        assert_eq!(we.to_string(), "verification-failed");
    }

    #[test]
    fn test_to_worker_error_invalid_proof_no_payload() {
        let we: worker::Error = ApiError::InvalidProof.into();
        assert_eq!(we.to_string(), "invalid-proof");
    }

    #[test]
    fn test_to_worker_error_unauthorized_no_payload() {
        let we: worker::Error = ApiError::Unauthorized.into();
        assert_eq!(we.to_string(), "unauthorized");
    }

    #[test]
    fn test_to_worker_error_unsupported_media_type_no_payload() {
        let we: worker::Error = ApiError::UnsupportedMediaType.into();
        assert_eq!(we.to_string(), "unsupported-media-type");
    }

    /* ========================================================================== */
    /*                    ErrorBody serialisation with field/detail              */
    /* ========================================================================== */

    #[test]
    fn test_error_body_with_field_and_detail() -> Result<(), Box<dyn std::error::Error>> {
        let body = ErrorBody {
            error: "Invalid request".to_string(),
            code: Some("ORIGIN_MISSING".to_string()),
            field: Some("Origin".to_string()),
            detail: Some("Origin header is required".to_string()),
            request_id: "test-id".to_string(),
        };
        let json = serde_json::to_string(&body)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        let obj = parsed.as_object().ok_or("expected object")?;
        assert_eq!(obj.len(), 5);
        assert_eq!(obj.get("field").and_then(|v| v.as_str()), Some("Origin"));
        assert_eq!(
            obj.get("detail").and_then(|v| v.as_str()),
            Some("Origin header is required")
        );
        Ok(())
    }

    #[test]
    fn test_error_body_null_field_null_detail_present() -> Result<(), Box<dyn std::error::Error>> {
        // W7-B3: field and detail must always appear (as null when absent)
        let body = ErrorBody {
            error: "test".to_string(),
            code: Some("TEST".to_string()),
            field: None,
            detail: None,
            request_id: "id".to_string(),
        };
        let json = serde_json::to_string(&body)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        let obj = parsed.as_object().ok_or("expected object")?;
        assert!(obj.contains_key("field"));
        assert!(obj.contains_key("detail"));
        assert!(obj.get("field").is_some_and(|v| v.is_null()));
        assert!(obj.get("detail").is_some_and(|v| v.is_null()));
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: All error variants can be converted to strings
        #[test]
        fn prop_all_errors_have_string_repr(
            msg in proptest::option::of("[a-zA-Z0-9 ]{0,100}")
        ) {
            let errors = vec![
                ApiError::BadRequest(msg.clone()),
                ApiError::NotFound,
                ApiError::Conflict(msg.clone()),
                ApiError::Gone(msg.clone()),
                ApiError::VerificationFailed,
                ApiError::InvalidProof,
                ApiError::Unauthorized,
                ApiError::Forbidden(msg.clone()),
                ApiError::PayloadTooLarge(msg.clone()),
                ApiError::UnsupportedMediaType,
                ApiError::TooManyRequests(msg.clone()),
                ApiError::PaymentRequired(msg.clone()),
                ApiError::ServiceUnavailable(msg.clone()),
            ];

            for err in errors {
                let s = err.to_string();
                prop_assert!(!s.is_empty());
                prop_assert!(s.len() < 100); // Error string should be concise
            }
        }

        /// Property: is_security_relevant is consistent
        #[test]
        fn prop_security_relevance_consistent(count in 0usize..10) {
            let security_errors = vec![
                ApiError::Unauthorized,
                ApiError::Forbidden(None),
                ApiError::VerificationFailed,
                ApiError::InvalidProof,
            ];

            for _ in 0..count {
                for err in &security_errors {
                    prop_assert!(err.is_security_relevant());
                }
            }
        }

        /// Property: Non-security errors are never security-relevant
        #[test]
        fn prop_non_security_errors(msg in proptest::option::of("[a-zA-Z0-9]{0,50}")) {
            let non_security_errors = vec![
                ApiError::BadRequest(msg.clone()),
                ApiError::NotFound,
                ApiError::Conflict(msg.clone()),
                ApiError::Gone(msg.clone()),
                ApiError::PayloadTooLarge(msg.clone()),
                ApiError::UnsupportedMediaType,
                ApiError::TooManyRequests(msg.clone()),
                ApiError::PaymentRequired(msg.clone()),
                ApiError::ServiceUnavailable(msg.clone()),
            ];

            for err in non_security_errors {
                prop_assert!(!err.is_security_relevant());
            }
        }

        /// Property: Optional messages can be any valid string
        #[test]
        fn prop_optional_message_any_string(msg in ".*") {
            let with_msg = ApiError::BadRequest(Some(msg.clone()));
            if let ApiError::BadRequest(Some(inner)) = with_msg {
                prop_assert_eq!(inner, msg);
            }
        }

        /// Property: Error variants with None option work correctly
        #[test]
        fn prop_none_option_variants(_seed in any::<u64>()) {
            let errors = vec![
                ApiError::BadRequest(None),
                ApiError::Conflict(None),
                ApiError::Gone(None),
                ApiError::Forbidden(None),
                ApiError::PayloadTooLarge(None),
                ApiError::TooManyRequests(None),
                ApiError::PaymentRequired(None),
                ApiError::ServiceUnavailable(None),
            ];

            for err in errors {
                let s = err.to_string();
                prop_assert!(!s.is_empty());
            }
        }

        /// Property: Error to string conversion is deterministic
        #[test]
        fn prop_error_string_deterministic(msg in proptest::option::of("[a-zA-Z0-9]{0,50}")) {
            let err1 = ApiError::BadRequest(msg.clone());
            let err2 = ApiError::BadRequest(msg.clone());
            prop_assert_eq!(err1.to_string(), err2.to_string());
        }

        /// Property: Security classification is deterministic
        #[test]
        fn prop_security_classification_deterministic(_seed in any::<u64>()) {
            let err1 = ApiError::Unauthorized;
            let err2 = ApiError::Unauthorized;
            prop_assert_eq!(err1.is_security_relevant(), err2.is_security_relevant());
        }

        /// Property: All 4xx errors are client errors
        #[test]
        fn prop_client_error_ranges(msg in proptest::option::of("[a-zA-Z]{0,20}")) {
            let client_errors = vec![
                ApiError::BadRequest(msg.clone()),
                ApiError::Unauthorized,
                ApiError::Forbidden(msg.clone()),
                ApiError::NotFound,
                ApiError::Conflict(msg.clone()),
                ApiError::Gone(msg.clone()),
                ApiError::PayloadTooLarge(msg.clone()),
                ApiError::UnsupportedMediaType,
                ApiError::VerificationFailed,
                ApiError::InvalidProof,
            ];

            // All client errors should have descriptive string representations
            for err in client_errors {
                let s = err.to_string();
                prop_assert!(!s.is_empty());
                prop_assert!(s.len() >= 4); // Minimum is "gone" (4 chars)
            }
        }

        /// Property: Internal errors wrap anyhow errors
        #[test]
        fn prop_internal_wraps_anyhow(msg in "[a-zA-Z0-9 ]{1,100}") {
            let anyhow_err = anyhow::anyhow!("{}", msg);
            let api_err = ApiError::Internal(anyhow_err);
            let err_str = api_err.to_string();
            prop_assert_eq!(err_str, "internal-server-error");
        }

        /// Property: Error body serialisation always produces valid JSON
        #[test]
        fn prop_error_body_valid_json(
            error_msg in "[a-zA-Z0-9 ]{1,100}",
            code in proptest::option::of("[A-Z_]{1,30}")
        ) {
            let body = ErrorBody {
                error: error_msg.clone(),
                code: code.clone(),
                field: None,
                detail: None,
                request_id: "prop-test-id".to_string(),
            };
            let json = serde_json::to_string(&body);
            prop_assert!(json.is_ok());

            let json_str = json.map_err(|e| proptest::test_runner::TestCaseError::Fail(e.to_string().into()))?;
            prop_assert!(json_str.contains(&error_msg));
            if let Some(c) = code {
                prop_assert!(json_str.contains(&c));
            }
        }

        /// Property: From conversions never panic and preserve the error variant
        #[test]
        fn prop_conversions_never_panic(msg in "[a-zA-Z0-9 ]{0,100}") {
            let anyhow_err = anyhow::anyhow!("{}", msg);
            let api_err: ApiError = anyhow_err.into();
            // The anyhow error should convert to an Internal variant
            let is_internal = matches!(&api_err, ApiError::Internal(_));
            prop_assert!(is_internal, "anyhow errors must convert to ApiError::Internal");
            let worker_err: worker::Error = api_err.into();
            let display = worker_err.to_string();
            // Display is "internal-server-error" from the #[error] attribute
            prop_assert!(display.contains("internal"), "worker::Error display must contain 'internal', got: {}", display);
        }

        /// Property: encode then decode is identity for structured details
        #[test]
        fn prop_encode_decode_roundtrip(
            code in proptest::option::of("[A-Z_]{1,20}"),
            field in proptest::option::of("[a-zA-Z0-9_]{1,20}"),
            detail in proptest::option::of("[a-zA-Z0-9 ]{0,50}")
        ) {
            let d = ErrorDetail {
                code: code.clone(),
                field: field.clone(),
                detail: detail.clone(),
            };
            let encoded = encode_structured_detail(&d);
            let decoded = match decode_structured_detail(&encoded) {
                Some(d) => d,
                None => return Err(proptest::test_runner::TestCaseError::fail("decode returned None")),
            };
            // The encoder maps None to "" and the decoder maps "" back to None,
            // so Some("") does NOT survive a round-trip (it collapses to None).
            // Pipes in field/detail are replaced with "/" during encoding.
            fn normalise(opt: Option<String>) -> Option<String> {
                opt.map(|s| s.replace('|', "/")).filter(|s| !s.is_empty())
            }
            let expected_code = code.filter(|s| !s.is_empty());
            let expected_field = normalise(field);
            let expected_detail = normalise(detail);
            prop_assert_eq!(&decoded.code, &expected_code);
            prop_assert_eq!(decoded.field, expected_field);
            prop_assert_eq!(decoded.detail, expected_detail);
        }

        /// Property: Debug representation contains variant name
        #[test]
        fn prop_debug_contains_variant(msg in proptest::option::of("[a-zA-Z]{0,20}")) {
            let errors: Vec<(&str, ApiError)> = vec![
                ("BadRequest", ApiError::BadRequest(msg.clone())),
                ("NotFound", ApiError::NotFound),
                ("Conflict", ApiError::Conflict(msg.clone())),
                ("Gone", ApiError::Gone(msg.clone())),
                ("VerificationFailed", ApiError::VerificationFailed),
                ("InvalidProof", ApiError::InvalidProof),
                ("Unauthorized", ApiError::Unauthorized),
                ("Forbidden", ApiError::Forbidden(msg.clone())),
                ("PayloadTooLarge", ApiError::PayloadTooLarge(msg.clone())),
                ("UnsupportedMediaType", ApiError::UnsupportedMediaType),
                ("TooManyRequests", ApiError::TooManyRequests(msg.clone())),
                ("PaymentRequired", ApiError::PaymentRequired(msg.clone())),
                ("ServiceUnavailable", ApiError::ServiceUnavailable(msg.clone())),
            ];

            for (name, err) in errors {
                let debug = format!("{:?}", err);
                prop_assert!(debug.contains(name));
            }
        }
    }

    /* ========================================================================== */
    /*  status_for_display_str: exhaustive per-variant individual tests          */
    /* ========================================================================== */

    #[test]
    fn test_status_for_display_str_not_found() {
        assert_eq!(
            ApiError::status_for_display_str("not-found"),
            Some((404, "NOT_FOUND"))
        );
    }

    #[test]
    fn test_status_for_display_str_conflict() {
        assert_eq!(
            ApiError::status_for_display_str("conflict"),
            Some((409, "CONFLICT"))
        );
    }

    #[test]
    fn test_status_for_display_str_gone() {
        assert_eq!(
            ApiError::status_for_display_str("gone"),
            Some((410, "GONE"))
        );
    }

    #[test]
    fn test_status_for_display_str_verification_failed() {
        assert_eq!(
            ApiError::status_for_display_str("verification-failed"),
            Some((400, "VERIFICATION_FAILED"))
        );
    }

    #[test]
    fn test_status_for_display_str_invalid_proof() {
        assert_eq!(
            ApiError::status_for_display_str("invalid-proof"),
            Some((400, "INVALID_PROOF"))
        );
    }

    #[test]
    fn test_status_for_display_str_payload_too_large() {
        assert_eq!(
            ApiError::status_for_display_str("payload-too-large"),
            Some((413, "PAYLOAD_TOO_LARGE"))
        );
    }

    #[test]
    fn test_status_for_display_str_unsupported_media_type() {
        assert_eq!(
            ApiError::status_for_display_str("unsupported-media-type"),
            Some((415, "UNSUPPORTED_MEDIA_TYPE"))
        );
    }

    #[test]
    fn test_status_for_display_str_too_many_requests() {
        assert_eq!(
            ApiError::status_for_display_str("too-many-requests"),
            Some((429, "TOO_MANY_REQUESTS"))
        );
    }

    #[test]
    fn test_status_for_display_str_payment_required() {
        assert_eq!(
            ApiError::status_for_display_str("payment-required"),
            Some((402, "PAYMENT_REQUIRED"))
        );
    }

    #[test]
    fn test_status_for_display_str_service_unavailable() {
        assert_eq!(
            ApiError::status_for_display_str("service-unavailable"),
            Some((503, "SERVICE_UNAVAILABLE"))
        );
    }

    #[test]
    fn test_status_for_display_str_internal_server_error() {
        assert_eq!(
            ApiError::status_for_display_str("internal-server-error"),
            Some((500, "INTERNAL_ERROR"))
        );
    }

    /* ========================================================================== */
    /*  status_for_display_str: envelope stripping (!! separator)                */
    /* ========================================================================== */

    #[test]
    fn test_status_for_display_str_strips_envelope_payload() {
        // When a display string has been propagated with `!!payload`, the base
        // token before `!!` must still resolve correctly.
        assert_eq!(
            ApiError::status_for_display_str("forbidden!!some-sentinel-data"),
            Some((403, "FORBIDDEN"))
        );
    }

    #[test]
    fn test_status_for_display_str_strips_envelope_gone() {
        assert_eq!(
            ApiError::status_for_display_str("gone!!__SD__|CHALLENGE_EXPIRED||ttl exceeded"),
            Some((410, "GONE"))
        );
    }

    #[test]
    fn test_status_for_display_str_strips_envelope_conflict() {
        assert_eq!(
            ApiError::status_for_display_str("conflict!!payload"),
            Some((409, "CONFLICT"))
        );
    }

    #[test]
    fn test_status_for_display_str_strips_envelope_unknown_base() {
        assert_eq!(
            ApiError::status_for_display_str("random-string!!payload"),
            None
        );
    }

    /* ========================================================================== */
    /*  extract_payload: structured sentinel without status override              */
    /* ========================================================================== */

    #[test]
    fn test_extract_payload_structured_no_status_override() -> Result<(), Box<dyn std::error::Error>>
    {
        let inner = encode_structured_detail(
            &ErrorDetail::new()
                .code("ORIGIN_MISSING")
                .field("Origin")
                .detail("required"),
        );
        let payload = Some(inner);
        let (status, detail) = ApiError::extract_payload(&payload);
        assert_eq!(status, None);
        let d = detail.ok_or("expected detail")?;
        assert_eq!(d.code.as_deref(), Some("ORIGIN_MISSING"));
        assert_eq!(d.field.as_deref(), Some("Origin"));
        assert_eq!(d.detail.as_deref(), Some("required"));
        Ok(())
    }

    /* ========================================================================== */
    /*  extract_payload: __STATUS:NNN prefix edge cases                          */
    /* ========================================================================== */

    #[test]
    fn test_extract_payload_status_prefix_missing_terminator() {
        // __STATUS:401 without trailing __ should not parse as an override
        let payload = Some("__STATUS:401foobar".to_string());
        let (status, _detail) = ApiError::extract_payload(&payload);
        assert_eq!(status, None);
    }

    #[test]
    fn test_extract_payload_status_prefix_empty_number() {
        let payload = Some("__STATUS:__rest".to_string());
        let (status, _detail) = ApiError::extract_payload(&payload);
        // Empty string between colons fails u16 parse
        assert_eq!(status, None);
    }

    #[test]
    fn test_extract_payload_status_prefix_large_number() {
        // u16::MAX + 1 should fail parse
        let payload = Some("__STATUS:65536__rest".to_string());
        let (status, _detail) = ApiError::extract_payload(&payload);
        assert_eq!(status, None);
    }

    #[test]
    fn test_extract_payload_status_prefix_zero() -> Result<(), Box<dyn std::error::Error>> {
        let inner = encode_structured_detail(&ErrorDetail::new().code("TEST"));
        let payload = Some(format!("__STATUS:0__{}", inner));
        let (status, detail) = ApiError::extract_payload(&payload);
        assert_eq!(status, Some(0));
        let d = detail.ok_or("expected detail")?;
        assert_eq!(d.code.as_deref(), Some("TEST"));
        Ok(())
    }

    /* ========================================================================== */
    /*  ApiError -> worker::Error: variants with payloads                        */
    /* ========================================================================== */

    #[test]
    fn test_to_worker_error_payload_too_large_with_payload() {
        let we: worker::Error = ApiError::PayloadTooLarge(Some("exceeded 10MB".to_string())).into();
        let s = we.to_string();
        assert!(s.starts_with("payload-too-large!!"));
        assert!(s.contains("exceeded 10MB"));
    }

    #[test]
    fn test_to_worker_error_too_many_requests_with_payload() {
        let we: worker::Error = ApiError::TooManyRequests(Some("rate limited".to_string())).into();
        let s = we.to_string();
        assert!(s.starts_with("too-many-requests!!"));
        assert!(s.contains("rate limited"));
    }

    #[test]
    fn test_to_worker_error_payment_required_with_payload() {
        let we: worker::Error =
            ApiError::PaymentRequired(Some("no credits left".to_string())).into();
        let s = we.to_string();
        assert!(s.starts_with("payment-required!!"));
        assert!(s.contains("no credits left"));
    }

    #[test]
    fn test_to_worker_error_service_unavailable_with_payload() {
        let we: worker::Error = ApiError::ServiceUnavailable(Some("KV down".to_string())).into();
        let s = we.to_string();
        assert!(s.starts_with("service-unavailable!!"));
        assert!(s.contains("KV down"));
    }

    #[test]
    fn test_to_worker_error_gone_with_payload() {
        let we: worker::Error = ApiError::Gone(Some("challenge expired".to_string())).into();
        let s = we.to_string();
        assert!(s.starts_with("gone!!"));
        assert!(s.contains("challenge expired"));
    }

    #[test]
    fn test_to_worker_error_forbidden_with_payload() {
        let we: worker::Error = ApiError::Forbidden(Some("not allowed".to_string())).into();
        let s = we.to_string();
        assert!(s.starts_with("forbidden!!"));
        assert!(s.contains("not allowed"));
    }

    /* ========================================================================== */
    /*  ApiError -> worker::Error: payloadless variants                          */
    /* ========================================================================== */

    #[test]
    fn test_to_worker_error_payload_too_large_none() {
        let we: worker::Error = ApiError::PayloadTooLarge(None).into();
        assert_eq!(we.to_string(), "payload-too-large");
    }

    #[test]
    fn test_to_worker_error_too_many_requests_none() {
        let we: worker::Error = ApiError::TooManyRequests(None).into();
        assert_eq!(we.to_string(), "too-many-requests");
    }

    #[test]
    fn test_to_worker_error_payment_required_none() {
        let we: worker::Error = ApiError::PaymentRequired(None).into();
        assert_eq!(we.to_string(), "payment-required");
    }

    #[test]
    fn test_to_worker_error_service_unavailable_none() {
        let we: worker::Error = ApiError::ServiceUnavailable(None).into();
        assert_eq!(we.to_string(), "service-unavailable");
    }

    #[test]
    fn test_to_worker_error_gone_none() {
        let we: worker::Error = ApiError::Gone(None).into();
        assert_eq!(we.to_string(), "gone");
    }

    #[test]
    fn test_to_worker_error_conflict_none() {
        let we: worker::Error = ApiError::Conflict(None).into();
        assert_eq!(we.to_string(), "conflict");
    }

    #[test]
    fn test_to_worker_error_forbidden_none() {
        let we: worker::Error = ApiError::Forbidden(None).into();
        assert_eq!(we.to_string(), "forbidden");
    }

    #[test]
    fn test_to_worker_error_internal() {
        let we: worker::Error = ApiError::Internal(anyhow::anyhow!("db fail")).into();
        assert_eq!(we.to_string(), "internal-server-error");
    }

    /* ========================================================================== */
    /*  Full round-trip: ApiError -> WorkerError -> parse_display_envelope ->     */
    /*  extract_payload for each payload-carrying variant                        */
    /* ========================================================================== */

    #[test]
    fn test_payload_too_large_structured_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::PayloadTooLarge(Some(encode_structured_detail(
            &ErrorDetail::new()
                .code("BODY_TOO_LARGE")
                .detail("exceeded 10MB"),
        )));
        let we: WorkerError = err.into();
        let s = we.to_string();
        let (base, payload) = ApiError::parse_display_envelope(&s);
        assert_eq!(base, "payload-too-large");
        let (status_override, detail) = ApiError::extract_payload(&payload);
        assert_eq!(status_override, None);
        let d = detail.ok_or("expected detail")?;
        assert_eq!(d.code.as_deref(), Some("BODY_TOO_LARGE"));
        assert_eq!(d.detail.as_deref(), Some("exceeded 10MB"));
        Ok(())
    }

    #[test]
    fn test_too_many_requests_structured_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::TooManyRequests(Some(encode_structured_detail(
            &ErrorDetail::new()
                .code("RATE_LIMIT_EXCEEDED")
                .detail("try later"),
        )));
        let we: WorkerError = err.into();
        let s = we.to_string();
        let (base, payload) = ApiError::parse_display_envelope(&s);
        assert_eq!(base, "too-many-requests");
        let (_status, detail) = ApiError::extract_payload(&payload);
        let d = detail.ok_or("expected detail")?;
        assert_eq!(d.code.as_deref(), Some("RATE_LIMIT_EXCEEDED"));
        Ok(())
    }

    #[test]
    fn test_payment_required_structured_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::PaymentRequired(Some(encode_structured_detail(
            &ErrorDetail::new()
                .code("INSUFFICIENT_CREDITS")
                .detail("top up required"),
        )));
        let we: WorkerError = err.into();
        let s = we.to_string();
        let (base, _payload) = ApiError::parse_display_envelope(&s);
        assert_eq!(base, "payment-required");
        assert!(s.contains("INSUFFICIENT_CREDITS"));
        Ok(())
    }

    /* ========================================================================== */
    /*  ErrorDetail: clone, debug, partial eq edge cases                         */
    /* ========================================================================== */

    #[test]
    fn test_error_detail_clone() {
        let d = ErrorDetail::new().code("A").field("B").detail("C");
        let d2 = d.clone();
        assert_eq!(d, d2);
    }

    #[test]
    fn test_error_detail_debug_format() {
        let d = ErrorDetail::new().code("TEST_CODE");
        let debug = format!("{:?}", d);
        assert!(debug.contains("TEST_CODE"));
        assert!(debug.contains("ErrorDetail"));
    }

    #[test]
    fn test_error_detail_ne_field_differs() {
        let a = ErrorDetail::new().code("A").field("X");
        let b = ErrorDetail::new().code("A").field("Y");
        assert_ne!(a, b);
    }

    #[test]
    fn test_error_detail_ne_detail_differs() {
        let a = ErrorDetail::new().code("A").detail("foo");
        let b = ErrorDetail::new().code("A").detail("bar");
        assert_ne!(a, b);
    }

    #[test]
    fn test_error_detail_eq_all_none() {
        let a = ErrorDetail::new();
        let b = ErrorDetail::new();
        assert_eq!(a, b);
    }

    #[test]
    fn test_error_detail_eq_all_fields_populated() {
        let a = ErrorDetail::new().code("C").field("F").detail("D");
        let b = ErrorDetail::new().code("C").field("F").detail("D");
        assert_eq!(a, b);
    }

    /* ========================================================================== */
    /*  decode_structured_detail: edge cases                                      */
    /* ========================================================================== */

    #[test]
    fn test_decode_sentinel_only_no_pipes() {
        // Just the sentinel with no pipe-separated parts after it.
        let result = decode_structured_detail(STRUCTURED_DETAIL_SENTINEL);
        // splitn(4, '|') on "__SD__" yields ["__SD__"], head matches the
        // sentinel, then parts.next() for code/field/detail all return None
        // which unwrap_or("") maps to "". All three empty strings become None
        // fields, so the function returns Some(ErrorDetail { all None }).
        let d = result.expect("sentinel-only input should decode to Some");
        assert_eq!(d.code, None);
        assert_eq!(d.field, None);
        assert_eq!(d.detail, None);
    }

    #[test]
    fn test_decode_sentinel_one_pipe() -> Result<(), Box<dyn std::error::Error>> {
        let input = format!("{}|MYCODE", STRUCTURED_DETAIL_SENTINEL);
        let d = decode_structured_detail(&input).ok_or("decode failed")?;
        assert_eq!(d.code.as_deref(), Some("MYCODE"));
        assert_eq!(d.field, None);
        assert_eq!(d.detail, None);
        Ok(())
    }

    #[test]
    fn test_decode_sentinel_two_pipes() -> Result<(), Box<dyn std::error::Error>> {
        let input = format!("{}|CODE|FIELD", STRUCTURED_DETAIL_SENTINEL);
        let d = decode_structured_detail(&input).ok_or("decode failed")?;
        assert_eq!(d.code.as_deref(), Some("CODE"));
        assert_eq!(d.field.as_deref(), Some("FIELD"));
        assert_eq!(d.detail, None);
        Ok(())
    }

    #[test]
    fn test_decode_sentinel_detail_with_pipes_preserved() -> Result<(), Box<dyn std::error::Error>>
    {
        // splitn(4, '|') means the 4th segment captures everything after the
        // third pipe, including any further pipes.
        let input = format!(
            "{}|CODE|FIELD|detail|with|pipes",
            STRUCTURED_DETAIL_SENTINEL
        );
        let d = decode_structured_detail(&input).ok_or("decode failed")?;
        assert_eq!(d.code.as_deref(), Some("CODE"));
        assert_eq!(d.field.as_deref(), Some("FIELD"));
        assert_eq!(d.detail.as_deref(), Some("detail|with|pipes"));
        Ok(())
    }

    #[test]
    fn test_decode_wrong_sentinel_prefix() {
        assert!(decode_structured_detail("__WRONG__|CODE||").is_none());
    }

    /* ========================================================================== */
    /*  encode_structured_detail: edge cases                                      */
    /* ========================================================================== */

    #[test]
    fn test_encode_all_empty_fields() {
        let d = ErrorDetail::new();
        let encoded = encode_structured_detail(&d);
        assert!(encoded.starts_with(STRUCTURED_DETAIL_SENTINEL));
        // All three trailing segments should be empty
        assert_eq!(encoded, format!("{}|||", STRUCTURED_DETAIL_SENTINEL));
    }

    #[test]
    fn test_encode_detail_only() -> Result<(), Box<dyn std::error::Error>> {
        let d = ErrorDetail::new().detail("some detail");
        let encoded = encode_structured_detail(&d);
        let decoded = decode_structured_detail(&encoded).ok_or("decode failed")?;
        assert_eq!(decoded.code, None);
        assert_eq!(decoded.field, None);
        assert_eq!(decoded.detail.as_deref(), Some("some detail"));
        Ok(())
    }

    #[test]
    fn test_encode_field_only() -> Result<(), Box<dyn std::error::Error>> {
        let d = ErrorDetail::new().field("Origin");
        let encoded = encode_structured_detail(&d);
        let decoded = decode_structured_detail(&encoded).ok_or("decode failed")?;
        assert_eq!(decoded.code, None);
        assert_eq!(decoded.field.as_deref(), Some("Origin"));
        assert_eq!(decoded.detail, None);
        Ok(())
    }

    #[test]
    fn test_encode_multiple_pipes_in_field_and_detail() -> Result<(), Box<dyn std::error::Error>> {
        let d = ErrorDetail {
            code: Some("CODE".to_string()),
            field: Some("a|b|c".to_string()),
            detail: Some("d|e|f".to_string()),
        };
        let encoded = encode_structured_detail(&d);
        let decoded = decode_structured_detail(&encoded).ok_or("decode failed")?;
        assert_eq!(decoded.field.as_deref(), Some("a/b/c"));
        assert_eq!(decoded.detail.as_deref(), Some("d/e/f"));
        Ok(())
    }

    /* ========================================================================== */
    /*  ErrorBody serialisation: full 5-key envelope with populated fields       */
    /* ========================================================================== */

    #[test]
    fn test_error_body_all_fields_populated() -> Result<(), Box<dyn std::error::Error>> {
        let body = ErrorBody {
            error: "Invalid request".to_string(),
            code: Some("ORIGIN_MISSING".to_string()),
            field: Some("Origin".to_string()),
            detail: Some("Origin header is required".to_string()),
            request_id: "req-123".to_string(),
        };
        let json = serde_json::to_string(&body)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        let obj = parsed.as_object().ok_or("expected object")?;
        assert_eq!(obj.len(), 5);
        assert_eq!(
            obj.get("error").and_then(|v| v.as_str()),
            Some("Invalid request")
        );
        assert_eq!(
            obj.get("code").and_then(|v| v.as_str()),
            Some("ORIGIN_MISSING")
        );
        assert_eq!(obj.get("field").and_then(|v| v.as_str()), Some("Origin"));
        assert_eq!(
            obj.get("detail").and_then(|v| v.as_str()),
            Some("Origin header is required")
        );
        assert_eq!(
            obj.get("request_id").and_then(|v| v.as_str()),
            Some("req-123")
        );
        Ok(())
    }

    #[test]
    fn test_error_body_code_none_skipped() -> Result<(), Box<dyn std::error::Error>> {
        let body = ErrorBody {
            error: "err".to_string(),
            code: None,
            field: Some("f".to_string()),
            detail: Some("d".to_string()),
            request_id: "id".to_string(),
        };
        let json = serde_json::to_string(&body)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        let obj = parsed.as_object().ok_or("expected object")?;
        // code has skip_serializing_if, so when None it is absent
        assert!(!obj.contains_key("code"));
        // field and detail are present (no skip_serializing_if)
        assert!(obj.contains_key("field"));
        assert!(obj.contains_key("detail"));
        Ok(())
    }

    /* ========================================================================== */
    /*  ErrorDetail From impls: additional edge cases                             */
    /* ========================================================================== */

    #[test]
    fn test_error_detail_from_str_long_message() {
        let long = "x".repeat(5000);
        let d = ErrorDetail::from(long.as_str());
        assert_eq!(d.detail.as_deref(), Some(long.as_str()));
    }

    #[test]
    fn test_error_detail_from_string_unicode() {
        let d = ErrorDetail::from("emoji: \u{1f600}".to_string());
        assert_eq!(d.detail.as_deref(), Some("emoji: \u{1f600}"));
    }

    /* ========================================================================== */
    /*  worker::Error -> ApiError conversion                                     */
    /* ========================================================================== */

    #[test]
    fn test_worker_error_jserror_to_api_error() {
        let we = worker::Error::RustError("JS runtime panic".to_string());
        let api_err: ApiError = we.into();
        assert!(matches!(api_err, ApiError::Internal(_)));
        assert_eq!(api_err.to_string(), "internal-server-error");
    }

    #[test]
    fn test_worker_error_to_api_error_preserves_message() {
        let we = worker::Error::RustError("specific failure detail".to_string());
        let api_err: ApiError = we.into();
        if let ApiError::Internal(inner) = api_err {
            assert!(inner.to_string().contains("specific failure detail"));
        } else {
            panic!("expected Internal variant"); // nosemgrep: provii.workers.panic-in-worker
        }
    }

    /* ========================================================================== */
    /*  Structured constructor round-trips through worker::Error                 */
    /* ========================================================================== */

    #[test]
    fn test_bad_request_with_field_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::bad_request(
            "INVALID_PKCE_VERIFIER",
            Some("code_verifier"),
            "PKCE verifier invalid",
        );
        let we: WorkerError = err.into();
        let s = we.to_string();
        let (base, payload) = ApiError::parse_display_envelope(&s);
        assert_eq!(base, "bad-request");
        let (_status, detail) = ApiError::extract_payload(&payload);
        let d = detail.ok_or("expected detail")?;
        assert_eq!(d.code.as_deref(), Some("INVALID_PKCE_VERIFIER"));
        assert_eq!(d.field.as_deref(), Some("code_verifier"));
        assert_eq!(d.detail.as_deref(), Some("PKCE verifier invalid"));
        Ok(())
    }

    #[test]
    fn test_gone_constructor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::gone("CHALLENGE_EXPIRED", "challenge TTL exceeded");
        let we: WorkerError = err.into();
        let s = we.to_string();
        let (base, payload) = ApiError::parse_display_envelope(&s);
        assert_eq!(base, "gone");
        let (_status, detail) = ApiError::extract_payload(&payload);
        let d = detail.ok_or("expected detail")?;
        assert_eq!(d.code.as_deref(), Some("CHALLENGE_EXPIRED"));
        assert_eq!(d.detail.as_deref(), Some("challenge TTL exceeded"));
        Ok(())
    }

    #[test]
    fn test_conflict_constructor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::conflict("CHALLENGE_ALREADY_REDEEMED", "already used");
        let we: WorkerError = err.into();
        let s = we.to_string();
        let (base, payload) = ApiError::parse_display_envelope(&s);
        assert_eq!(base, "conflict");
        let (_status, detail) = ApiError::extract_payload(&payload);
        let d = detail.ok_or("expected detail")?;
        assert_eq!(d.code.as_deref(), Some("CHALLENGE_ALREADY_REDEEMED"));
        Ok(())
    }

    #[test]
    fn test_service_unavailable_constructor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::service_unavailable("DO_STORE_FAILED", "Durable Object unavailable");
        let we: WorkerError = err.into();
        let s = we.to_string();
        let (base, payload) = ApiError::parse_display_envelope(&s);
        assert_eq!(base, "service-unavailable");
        let (_status, detail) = ApiError::extract_payload(&payload);
        let d = detail.ok_or("expected detail")?;
        assert_eq!(d.code.as_deref(), Some("DO_STORE_FAILED"));
        assert_eq!(d.detail.as_deref(), Some("Durable Object unavailable"));
        Ok(())
    }

    #[test]
    fn test_forbidden_constructor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::forbidden("ORIGIN_DISABLED", "origin has been disabled");
        let we: WorkerError = err.into();
        let s = we.to_string();
        let (base, payload) = ApiError::parse_display_envelope(&s);
        assert_eq!(base, "forbidden");
        let (_status, detail) = ApiError::extract_payload(&payload);
        let d = detail.ok_or("expected detail")?;
        assert_eq!(d.code.as_deref(), Some("ORIGIN_DISABLED"));
        Ok(())
    }

    #[test]
    fn test_forbidden_with_field_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let err =
            ApiError::forbidden_with_field("CSRF_INVALID", "X-CSRF-Token", "CSRF token mismatch");
        let we: WorkerError = err.into();
        let s = we.to_string();
        let (base, payload) = ApiError::parse_display_envelope(&s);
        assert_eq!(base, "forbidden");
        let (_status, detail) = ApiError::extract_payload(&payload);
        let d = detail.ok_or("expected detail")?;
        assert_eq!(d.code.as_deref(), Some("CSRF_INVALID"));
        assert_eq!(d.field.as_deref(), Some("X-CSRF-Token"));
        assert_eq!(d.detail.as_deref(), Some("CSRF token mismatch"));
        Ok(())
    }

    #[test]
    fn test_unauthorized_constructor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let err = ApiError::unauthorized("NONCE_REPLAY", "nonce already used");
        let we: WorkerError = err.into();
        let s = we.to_string();
        let (base, payload) = ApiError::parse_display_envelope(&s);
        assert_eq!(base, "bad-request");
        let (status_override, detail) = ApiError::extract_payload(&payload);
        assert_eq!(status_override, Some(401));
        let d = detail.ok_or("expected detail")?;
        assert_eq!(d.code.as_deref(), Some("NONCE_REPLAY"));
        assert_eq!(d.detail.as_deref(), Some("nonce already used"));
        Ok(())
    }

    /* ========================================================================== */
    /*  Debug format: each variant                                               */
    /* ========================================================================== */

    #[test]
    fn test_not_found_debug_format() {
        let debug = format!("{:?}", ApiError::NotFound);
        assert!(debug.contains("NotFound"));
    }

    #[test]
    fn test_conflict_debug_format() {
        let debug = format!("{:?}", ApiError::Conflict(Some("dup".to_string())));
        assert!(debug.contains("Conflict"));
        assert!(debug.contains("dup"));
    }

    #[test]
    fn test_gone_debug_format() {
        let debug = format!("{:?}", ApiError::Gone(None));
        assert!(debug.contains("Gone"));
    }

    #[test]
    fn test_verification_failed_debug_format() {
        let debug = format!("{:?}", ApiError::VerificationFailed);
        assert!(debug.contains("VerificationFailed"));
    }

    #[test]
    fn test_invalid_proof_debug_format() {
        let debug = format!("{:?}", ApiError::InvalidProof);
        assert!(debug.contains("InvalidProof"));
    }

    #[test]
    fn test_unauthorized_debug_format() {
        let debug = format!("{:?}", ApiError::Unauthorized);
        assert!(debug.contains("Unauthorized"));
    }

    #[test]
    fn test_forbidden_debug_format() {
        let debug = format!("{:?}", ApiError::Forbidden(None));
        assert!(debug.contains("Forbidden"));
    }

    #[test]
    fn test_payload_too_large_debug_format() {
        let debug = format!("{:?}", ApiError::PayloadTooLarge(None));
        assert!(debug.contains("PayloadTooLarge"));
    }

    #[test]
    fn test_unsupported_media_type_debug_format() {
        let debug = format!("{:?}", ApiError::UnsupportedMediaType);
        assert!(debug.contains("UnsupportedMediaType"));
    }

    #[test]
    fn test_too_many_requests_debug_format() {
        let debug = format!("{:?}", ApiError::TooManyRequests(None));
        assert!(debug.contains("TooManyRequests"));
    }

    #[test]
    fn test_payment_required_debug_format() {
        let debug = format!("{:?}", ApiError::PaymentRequired(None));
        assert!(debug.contains("PaymentRequired"));
    }

    #[test]
    fn test_service_unavailable_debug_format() {
        let debug = format!("{:?}", ApiError::ServiceUnavailable(None));
        assert!(debug.contains("ServiceUnavailable"));
    }

    #[test]
    fn test_internal_debug_format() {
        let debug = format!("{:?}", ApiError::Internal(anyhow::anyhow!("db down")));
        assert!(debug.contains("Internal"));
    }

    /* ========================================================================== */
    /*  is_security_relevant: variants with payloads                             */
    /* ========================================================================== */

    #[test]
    fn test_forbidden_with_payload_is_security_relevant() {
        assert!(ApiError::Forbidden(Some("origin not allowed".to_string())).is_security_relevant());
    }

    #[test]
    fn test_internal_with_payload_not_security_relevant() {
        assert!(!ApiError::Internal(anyhow::anyhow!("db fail")).is_security_relevant());
    }

    /* ========================================================================== */
    /*  ErrorDetail builder: overwrite chaining                                  */
    /* ========================================================================== */

    #[test]
    fn test_error_detail_builder_overwrites() {
        let d = ErrorDetail::new()
            .code("FIRST")
            .code("SECOND")
            .field("field1")
            .field("field2")
            .detail("detail1")
            .detail("detail2");
        assert_eq!(d.code.as_deref(), Some("SECOND"));
        assert_eq!(d.field.as_deref(), Some("field2"));
        assert_eq!(d.detail.as_deref(), Some("detail2"));
    }

    /* ========================================================================== */
    /*  parse_display_envelope: additional edge cases                             */
    /* ========================================================================== */

    #[test]
    fn test_parse_display_envelope_just_separator() {
        let (base, payload) = ApiError::parse_display_envelope("!!");
        assert_eq!(base, "");
        assert_eq!(payload.as_deref(), Some(""));
    }

    #[test]
    fn test_parse_display_envelope_trailing_separator() {
        let (base, payload) = ApiError::parse_display_envelope("forbidden!!");
        assert_eq!(base, "forbidden");
        assert_eq!(payload.as_deref(), Some(""));
    }

    /* ========================================================================== */
    /*  Service unavailable round-trip with structured constructor               */
    /* ========================================================================== */

    #[test]
    fn test_service_unavailable_round_trip_status() {
        let err = ApiError::service_unavailable("RANDOM_FAILURE", "entropy source failed");
        let we: WorkerError = err.into();
        let s = we.to_string();
        let (base, _) = ApiError::parse_display_envelope(&s);
        assert_eq!(
            ApiError::status_for_display_str(base),
            Some((503, "SERVICE_UNAVAILABLE"))
        );
    }

    /* ========================================================================== */
    /*  Too many requests round-trip status                                      */
    /* ========================================================================== */

    #[test]
    fn test_too_many_requests_round_trip_status() {
        let err = ApiError::TooManyRequests(Some("limit hit".to_string()));
        let we: WorkerError = err.into();
        let s = we.to_string();
        assert_eq!(
            ApiError::status_for_display_str(&s),
            Some((429, "TOO_MANY_REQUESTS"))
        );
    }

    /* ========================================================================== */
    /*  Payment required round-trip status                                       */
    /* ========================================================================== */

    #[test]
    fn test_payment_required_round_trip_status() {
        let err = ApiError::PaymentRequired(Some("no credits".to_string()));
        let we: WorkerError = err.into();
        let s = we.to_string();
        assert_eq!(
            ApiError::status_for_display_str(&s),
            Some((402, "PAYMENT_REQUIRED"))
        );
    }

    /* ========================================================================== */
    /*  Payload-too-large round-trip status                                      */
    /* ========================================================================== */

    #[test]
    fn test_payload_too_large_round_trip_status() {
        let err = ApiError::PayloadTooLarge(Some("body too big".to_string()));
        let we: WorkerError = err.into();
        let s = we.to_string();
        assert_eq!(
            ApiError::status_for_display_str(&s),
            Some((413, "PAYLOAD_TOO_LARGE"))
        );
    }

    /* ========================================================================== */
    /*  Gone round-trip status                                                   */
    /* ========================================================================== */

    #[test]
    fn test_gone_round_trip_status() {
        let err = ApiError::Gone(Some("expired".to_string()));
        let we: WorkerError = err.into();
        let s = we.to_string();
        assert_eq!(ApiError::status_for_display_str(&s), Some((410, "GONE")));
    }

    /* ========================================================================== */
    /*  Conflict round-trip status                                               */
    /* ========================================================================== */

    #[test]
    fn test_conflict_round_trip_status() {
        let err = ApiError::Conflict(Some("dup".to_string()));
        let we: WorkerError = err.into();
        let s = we.to_string();
        assert_eq!(
            ApiError::status_for_display_str(&s),
            Some((409, "CONFLICT"))
        );
    }

    /* ========================================================================== */
    /*  ApiResult alias                                                          */
    /* ========================================================================== */

    #[test]
    fn test_api_result_ok() -> Result<(), Box<dyn std::error::Error>> {
        let result: ApiResult<u32> = Ok(42);
        let val = result.map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
        assert_eq!(val, 42);
        Ok(())
    }

    #[test]
    fn test_api_result_err() {
        let result: ApiResult<u32> = Err(ApiError::NotFound);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*  ErrorDetail field() accepts Into<String>                                 */
    /* ========================================================================== */

    #[test]
    fn test_error_detail_field_string_owned() {
        let d = ErrorDetail::new().field(String::from("Origin"));
        assert_eq!(d.field.as_deref(), Some("Origin"));
    }

    #[test]
    fn test_error_detail_detail_string_owned() {
        let d = ErrorDetail::new().detail(String::from("header required"));
        assert_eq!(d.detail.as_deref(), Some("header required"));
    }

    /* ========================================================================== */
    /*  Display: variants with Some payload still produce stable Display          */
    /* ========================================================================== */

    #[test]
    fn test_service_unavailable_with_message_display() {
        let err = ApiError::ServiceUnavailable(Some("KV down".to_string()));
        assert_eq!(err.to_string(), "service-unavailable");
    }

    #[test]
    fn test_payload_too_large_with_message_display() {
        let err = ApiError::PayloadTooLarge(Some("exceeded 50MB".to_string()));
        assert_eq!(err.to_string(), "payload-too-large");
    }

    #[test]
    fn test_gone_with_message_display() {
        let err = ApiError::Gone(Some("expired challenge".to_string()));
        assert_eq!(err.to_string(), "gone");
    }

    #[test]
    fn test_conflict_with_message_display() {
        let err = ApiError::Conflict(Some("duplicate".to_string()));
        assert_eq!(err.to_string(), "conflict");
    }

    #[test]
    fn test_forbidden_with_message_display() {
        let err = ApiError::Forbidden(Some("blocked".to_string()));
        assert_eq!(err.to_string(), "forbidden");
    }

    #[test]
    fn test_is_security_relevant_too_many_requests_with_payload() {
        assert!(!ApiError::TooManyRequests(Some("burst".to_string())).is_security_relevant());
    }

    #[test]
    fn test_is_security_relevant_payment_required_with_payload() {
        assert!(!ApiError::PaymentRequired(Some("zero credits".to_string())).is_security_relevant());
    }

    #[test]
    fn test_is_security_relevant_gone_with_payload() {
        assert!(!ApiError::Gone(Some("expired".to_string())).is_security_relevant());
    }

    #[test]
    fn test_is_security_relevant_conflict_with_payload() {
        assert!(!ApiError::Conflict(Some("duplicate".to_string())).is_security_relevant());
    }

    #[test]
    fn test_is_security_relevant_bad_request_with_payload() {
        assert!(!ApiError::BadRequest(Some("missing field".to_string())).is_security_relevant());
    }

    #[test]
    fn test_is_security_relevant_payload_too_large_with_payload() {
        assert!(!ApiError::PayloadTooLarge(Some("50MB".to_string())).is_security_relevant());
    }

    #[test]
    fn test_status_for_display_str_empty_base_from_double_bang() {
        assert_eq!(ApiError::status_for_display_str("!!trailing"), None);
    }

    #[test]
    fn test_status_for_display_str_multiple_separators() {
        assert_eq!(
            ApiError::status_for_display_str("gone!!first!!second"),
            Some((410, "GONE"))
        );
    }

    #[test]
    fn test_status_for_display_str_case_sensitive() {
        assert_eq!(ApiError::status_for_display_str("Bad-Request"), None);
        assert_eq!(ApiError::status_for_display_str("FORBIDDEN"), None);
        assert_eq!(ApiError::status_for_display_str("Unauthorized"), None);
    }

    #[test]
    fn test_status_for_display_str_partial_match_returns_none() {
        assert_eq!(ApiError::status_for_display_str("bad-request-extra"), None);
        assert_eq!(ApiError::status_for_display_str("not-found-here"), None);
    }

    #[test]
    fn test_status_for_display_str_empty_string() {
        assert_eq!(ApiError::status_for_display_str(""), None);
    }
}
