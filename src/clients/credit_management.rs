// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Credit Management API Client
//!
//! Provides HTTP client for consuming credits and assigning royalties via the provii-credit-management API.
//! SSRF protection is applied to all outbound requests.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect};
use zeroize::Zeroizing;

use crate::utils::ssrf_protection::{
    validate_base_url, validate_content_type, validate_path_component, MAX_RESPONSE_BODY_BYTES,
};

type HmacSha256 = Hmac<Sha256>;

const MAX_RETRIES: usize = 3;
const INITIAL_BACKOFF_MS: u64 = 100;

/// Errors returned by the credit management client.
#[derive(Debug, Error)]
pub enum CreditError {
    #[error("Insufficient credits: {required} required, {available} available")]
    InsufficientCredits { required: u64, available: u64 },

    #[error("Credit service unavailable")]
    ServiceUnavailable,

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("HMAC signature error: {0}")]
    HmacError(String),

    #[error("SSRF validation error: {0}")]
    SsrfError(String),
}

/// Fields provided by the caller to describe the credit consumption.
#[derive(Debug, Clone)]
pub struct ConsumeCreditsRequest {
    /// Customer identifier for billing.
    pub customer_id: String,
    /// Unique ID of the verification being billed.
    pub verification_id: String,
    /// Origin domain of the relying party.
    pub origin: String,
    /// Optional issuer key ID for royalty attribution.
    pub issuer_kid: Option<String>,
    /// Environment for credit tracking (e.g. "production" or "sandbox").
    pub environment: String,
    /// Partner that provisioned this verifier, if any. Sent as
    /// `X-Partner-ID` header for revenue-share attribution. Not included
    /// in the JSON body (provii-credit-management uses `.strict()` Zod schema).
    pub partner_id: Option<String>,
}

/// Wire-level body sent to provii-credit-management's `/v1/credits/consume`.
/// Matches the `ConsumeCreditsSchema` Zod schema (`.strict()`).
/// Authentication fields (timestamp, HMAC) are sent in headers only.
#[derive(Debug, Clone, Serialize)]
struct ConsumeCreditsBody {
    customer_id: String,
    verification_id: String,
    origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<String>,
}

/// Successful response from the credit consumption endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct ConsumeCreditsResponse {
    /// Remaining credit balance after consumption, if reported.
    pub balance_after_units: Option<u64>,
    /// Royalty credits awarded to the issuer, if applicable.
    pub royalty_units_credited: Option<u64>,
}

/// Error payload returned by the credit management API on failure.
#[derive(Debug, Clone, Deserialize)]
pub struct ErrorResponse {
    /// Human-readable error message.
    pub error: String,
    /// Machine-readable error code (e.g. `INSUFFICIENT_CREDITS`).
    #[serde(default)]
    pub code: Option<String>,
    /// Available credit balance at the time of failure.
    #[serde(default)]
    pub available: Option<u64>,
    /// Credits required by the operation that failed.
    #[serde(default)]
    pub required: Option<u64>,
}

/// Credit Management API Client
///
/// Handles authentication via HMAC-SHA256 and implements retry logic with exponential backoff.
/// SSRF protection is applied to all outbound HTTP requests.
pub struct CreditManagementClient {
    base_url: String,
    hmac_key: Zeroizing<Vec<u8>>,
    key_id: String,
    env: Env,
}

impl CreditManagementClient {
    /// Create a new CreditManagementClient.
    ///
    /// # Arguments
    /// * `base_url` - Base URL of the provii-credit-management API (must be HTTPS, port 443)
    /// * `hmac_key_hex` - HMAC key for request signing (base64url-no-pad;
    ///   legacy hex accepted during the encoding migration)
    /// * `key_id` - Key ID for HMAC authentication
    /// * `env` - Worker environment for HTTP requests
    ///
    /// # Errors
    /// Returns an error if the HMAC key fails to decode or the base URL fails
    /// SSRF validation.
    pub fn new(
        base_url: String,
        hmac_key_hex: String,
        key_id: String,
        env: Env,
    ) -> Result<Self, CreditError> {
        // SSRF-070: Validate base URL scheme is HTTPS
        validate_base_url(&base_url)
            .map_err(|e| CreditError::SsrfError(format!("Invalid base URL: {}", e)))?;

        // Wrap encoded input so it is zeroised on drop
        let hmac_key_hex = Zeroizing::new(hmac_key_hex);
        let hmac_key = Zeroizing::new(Self::decode_hmac_key(hmac_key_hex.as_str())?);

        Ok(Self {
            base_url,
            hmac_key,
            key_id,
            env,
        })
    }

    /// Decode an HMAC key from its stored string encoding to raw bytes.
    ///
    /// The standardised encoding is base64url-no-pad (32 bytes -> 43 chars).
    /// Legacy hex (64 chars) is still accepted during the encoding migration so
    /// that environments minted under the old format keep working; signer and
    /// verifier decode identically. Remove the hex branch once every
    /// environment has been re-minted to base64url.
    fn decode_hmac_key(encoded: &str) -> Result<Vec<u8>, CreditError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        if encoded.len() == 43 {
            return URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|e| {
                CreditError::HmacError(format!("Failed to decode base64url HMAC key: {}", e))
            });
        }
        hex::decode(encoded.as_bytes())
            .map_err(|e| CreditError::HmacError(format!("Failed to decode HMAC key: {}", e)))
    }

    /// Consume credits for a verification.
    ///
    /// Implements retry logic with exponential backoff for transient failures.
    pub async fn consume_credits(
        &self,
        request: ConsumeCreditsRequest,
    ) -> Result<ConsumeCreditsResponse, CreditError> {
        let mut backoff_ms = INITIAL_BACKOFF_MS;

        for attempt in 1..=MAX_RETRIES {
            match self.consume_credits_once(&request).await {
                Ok(response) => return Ok(response),
                Err(CreditError::ServiceUnavailable) if attempt < MAX_RETRIES => {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[CreditClient] Attempt {}/{} failed (service unavailable), retrying in {}ms",
                        attempt,
                        MAX_RETRIES,
                        backoff_ms
                    );
                    // SB-004: Workers-compatible sleep using globalThis.setTimeout.
                    #[cfg(target_arch = "wasm32")]
                    {
                        let promise = js_sys::Promise::new(&mut |resolve, _| {
                            let global = js_sys::global();
                            let set_timeout =
                                match js_sys::Reflect::get(&global, &"setTimeout".into()) {
                                    Ok(val) => val,
                                    Err(_) => {
                                        // setTimeout unavailable, skip sleep, retry immediately
                                        resolve.call0(&wasm_bindgen::JsValue::NULL).ok();
                                        return;
                                    }
                                };
                            let set_timeout_fn = match set_timeout.dyn_into::<js_sys::Function>() {
                                Ok(f) => f,
                                Err(_) => {
                                    // setTimeout not a function, skip sleep, retry immediately
                                    resolve.call0(&wasm_bindgen::JsValue::NULL).ok();
                                    return;
                                }
                            };
                            // backoff_ms is capped at a few hundred by the retry
                            // count, so i32 truncation does not occur in practice.
                            #[allow(clippy::cast_possible_truncation)]
                            let delay_ms: i32 = backoff_ms.min(i32::MAX as u64) as i32;
                            let _ = set_timeout_fn.call2(&global, &resolve, &delay_ms.into());
                        });
                        let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        // Native fallback: no-op (tests do not exercise retry sleep)
                    }
                    backoff_ms = backoff_ms.saturating_mul(2);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Err(CreditError::ServiceUnavailable)
    }

    /// Internal method to make a single credit consumption request.
    ///
    /// SB-015: Clones the body string before creating the first RequestInit so that
    /// a fresh RequestInit with a new body can be built for the HTTP fallback path.
    async fn consume_credits_once(
        &self,
        request: &ConsumeCreditsRequest,
    ) -> Result<ConsumeCreditsResponse, CreditError> {
        // SSRF-071: Validate entity IDs before use in headers or potential URL construction
        validate_path_component(&request.customer_id, "customer_id")
            .map_err(|e| CreditError::InvalidRequest(format!("Invalid customer_id: {}", e)))?;
        validate_path_component(&request.verification_id, "verification_id")
            .map_err(|e| CreditError::InvalidRequest(format!("Invalid verification_id: {}", e)))?;
        if let Some(ref kid) = request.issuer_kid {
            validate_path_component(kid, "issuer_kid")
                .map_err(|e| CreditError::InvalidRequest(format!("Invalid issuer_kid: {}", e)))?;
        }

        let timestamp = worker::Date::now().as_millis() / 1000;
        let timestamp_str = timestamp.to_string();

        // P3-001: Generate UUID v4 nonce for replay prevention
        let nonce = uuid::Uuid::new_v4().to_string();

        let method = "POST";
        let path = "/v1/credits/consume";

        let env_str = match request.environment.as_str() {
            "production" => None,
            other => Some(other.to_string()),
        };

        // Serialise the body (no auth fields; timestamp and HMAC go in headers)
        let wire_body = ConsumeCreditsBody {
            customer_id: request.customer_id.clone(),
            verification_id: request.verification_id.clone(),
            origin: request.origin.clone(),
            issuer_kid: request.issuer_kid.clone(),
            environment: env_str,
        };
        let body = serde_json::to_string(&wire_body)
            .map_err(|e| CreditError::SerializationError(e.to_string()))?;

        // HMAC canonical message: timestamp:method:path:body
        let header_hmac = self.generate_hmac(&timestamp_str, method, path, &body)?;

        // Helper: build headers
        let build_headers = || -> Result<Headers, CreditError> {
            let headers = Headers::new();
            let set = |h: &Headers, k: &str, v: &str| -> Result<(), CreditError> {
                h.set(k, v).map_err(|e| {
                    CreditError::NetworkError(format!("Failed to set header: {:?}", e))
                })
            };
            set(&headers, "Content-Type", "application/json")?;
            set(&headers, "X-Timestamp", &timestamp_str)?;
            set(&headers, "X-HMAC", &header_hmac)?;
            set(&headers, "X-API-Key-ID", &self.key_id)?;
            set(&headers, "X-Nonce", &nonce)?;
            set(&headers, "X-Entity-Type", "customer")?;
            set(&headers, "X-Entity-ID", &request.customer_id)?;
            // JH-003: Propagate partner ID for revenue-share attribution.
            // Sent as header (not body) to avoid breaking the `.strict()` Zod
            // schema on provii-credit-management's consume endpoint.
            if let Some(ref pid) = request.partner_id {
                set(&headers, "X-Partner-ID", pid)?;
            }
            Ok(headers)
        };

        // PREFERRED: Try service binding first
        if let Ok(service) = self.env.service("CREDIT_MGMT") {
            // SSRF-075: Log domain only
            #[cfg(target_arch = "wasm32")]
            console_log!("[CreditClient] Using service binding for provii-credit-management");

            let sb_headers = build_headers()?;
            let mut sb_init = RequestInit::new();
            sb_init
                .with_method(Method::Post)
                .with_headers(sb_headers)
                .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));

            // Service binding URLs: hostname is ignored by the runtime, but
            // must be a syntactically valid HTTPS URL for Request construction.
            let url = "https://credit-mgmt.internal/v1/credits/consume";

            let req = Request::new_with_init(url, &sb_init).map_err(|e| {
                CreditError::NetworkError(format!(
                    "Failed to create service binding request: {:?}",
                    e
                ))
            })?;

            // Per-operation timeout for provii-credit-management service binding fetch.
            match crate::utils::timeout::with_timeout(
                "credit_management service binding fetch",
                crate::utils::timeout::DO_FETCH_TIMEOUT_MS,
                service.fetch_request(req),
            )
            .await
            {
                Ok(Ok(response)) => {
                    #[cfg(target_arch = "wasm32")]
                    console_log!("[CreditClient] Service binding request succeeded");
                    return self.parse_consume_response(response).await;
                }
                Ok(Err(_e)) => {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[CreditClient] Service binding failed, falling back to HTTP: {:?}",
                        _e
                    );
                }
                Err(_timeout_err) => {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[CreditClient] Service binding timed out, falling back to HTTP: {}",
                        _timeout_err
                    );
                }
            }
        }

        // FALLBACK: Use HTTP
        // SSRF-075: Log domain only
        #[cfg(target_arch = "wasm32")]
        console_log!("[CreditClient] Using HTTP fallback for provii-credit-management");

        let http_headers = build_headers()?;
        let mut http_init = RequestInit::new();
        http_init
            .with_method(Method::Post)
            .with_headers(http_headers)
            .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)))
            // SSRF-004: Block redirects
            .with_redirect(RequestRedirect::Error);

        let url = format!("{}/v1/credits/consume", self.base_url);

        let req = Request::new_with_init(&url, &http_init)
            .map_err(|e| CreditError::NetworkError(format!("Failed to create request: {:?}", e)))?;

        // Per-operation timeout for provii-credit-management HTTP fallback fetch.
        let response = crate::utils::timeout::with_timeout(
            "credit_management HTTP fetch",
            crate::utils::timeout::DO_FETCH_TIMEOUT_MS,
            Fetch::Request(req).send(),
        )
        .await
        .map_err(|e| CreditError::NetworkError(format!("Request timed out: {}", e)))?
        .map_err(|e| CreditError::NetworkError(format!("Request failed: {:?}", e)))?;

        self.parse_consume_response(response).await
    }

    /// Parse the response from a consume credits request.
    ///
    /// SSRF-011: Enforces response body size limit.
    /// SSRF-020: Validates Content-Type is application/json.
    async fn parse_consume_response(
        &self,
        mut response: worker::Response,
    ) -> Result<ConsumeCreditsResponse, CreditError> {
        let status = response.status_code();

        // SSRF-020: Validate Content-Type before parsing body (on success)
        if status == 200 {
            let content_type = response.headers().get("Content-Type").ok().flatten();
            validate_content_type(content_type).map_err(|e| {
                CreditError::NetworkError(format!("Content-Type validation failed: {}", e))
            })?;
        }

        // SSRF-011: Check Content-Length before reading body
        if let Ok(Some(cl_str)) = response.headers().get("Content-Length") {
            if let Ok(cl) = cl_str.parse::<usize>() {
                if cl > MAX_RESPONSE_BODY_BYTES {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[CreditClient] Response too large: {} bytes (max: {})",
                        cl,
                        MAX_RESPONSE_BODY_BYTES
                    );
                    return Err(CreditError::NetworkError(format!(
                        "Response body exceeds {} byte limit",
                        MAX_RESPONSE_BODY_BYTES
                    )));
                }
            }
        }

        // Read response body
        let response_text = response
            .text()
            .await
            .map_err(|e| CreditError::NetworkError(format!("Failed to read response: {:?}", e)))?;

        // SSRF-011: Enforce size limit on actual body
        if response_text.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(CreditError::NetworkError(format!(
                "Response body exceeds {} byte limit",
                MAX_RESPONSE_BODY_BYTES
            )));
        }

        match status {
            200 => serde_json::from_str::<ConsumeCreditsResponse>(&response_text).map_err(|e| {
                CreditError::SerializationError(format!("Failed to parse response: {}", e))
            }),
            401 => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "{{\"audit\":true,\"event\":\"credit_mgmt_call_failed\",\"severity\":\"error\",\"status_code\":401,\"error\":\"authentication_failure\"}}"
                );
                Err(CreditError::NetworkError(
                    "Provii-credit-management authentication failure (401)".to_string(),
                ))
            }
            403 => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "{{\"audit\":true,\"event\":\"credit_mgmt_call_failed\",\"severity\":\"error\",\"status_code\":403,\"error\":\"authorisation_failure\"}}"
                );
                Err(CreditError::NetworkError(
                    "Provii-credit-management authorisation failure (403)".to_string(),
                ))
            }
            402 => {
                let error_response = serde_json::from_str::<ErrorResponse>(&response_text)
                    .unwrap_or_else(|_| ErrorResponse {
                        error: "Insufficient credits".to_string(),
                        code: Some("INSUFFICIENT_CREDITS".to_string()),
                        available: None,
                        required: None,
                    });

                Err(CreditError::InsufficientCredits {
                    required: error_response.required.unwrap_or(1),
                    available: error_response.available.unwrap_or(0),
                })
            }
            409 => {
                let error_response = serde_json::from_str::<ErrorResponse>(&response_text)
                    .unwrap_or_else(|_| ErrorResponse {
                        error: "Conflict".to_string(),
                        code: Some("CONFLICT".to_string()),
                        available: None,
                        required: None,
                    });

                Err(CreditError::Conflict(error_response.error))
            }
            503 => Err(CreditError::ServiceUnavailable),
            400 => {
                let error_response = serde_json::from_str::<ErrorResponse>(&response_text)
                    .unwrap_or_else(|_| ErrorResponse {
                        error: "Invalid request".to_string(),
                        code: Some("BAD_REQUEST".to_string()),
                        available: None,
                        required: None,
                    });

                Err(CreditError::InvalidRequest(error_response.error))
            }
            _ => {
                // SB-024: Log raw upstream body server-side only
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[CreditClient] {} response body (server-side only): {}",
                    status,
                    response_text
                );
                Err(CreditError::NetworkError(format!(
                    "Unexpected status code {}",
                    status
                )))
            }
        }
    }

    /// Generate HMAC-SHA256 signature for request authentication.
    ///
    /// The signature is computed over: `timestamp:method:path:body`
    /// (matches provii-credit-management's `createCanonicalMessage` format).
    ///
    /// SB-023: This canonical format intentionally differs from the issuer-service
    /// client. The provii-credit-management service includes method and path in the
    /// canonical message because it serves multiple endpoints with distinct HTTP
    /// methods. Each format must match the receiver's verification logic exactly.
    fn generate_hmac(
        &self,
        timestamp: &str,
        method: &str,
        path: &str,
        body: &str,
    ) -> Result<String, CreditError> {
        let message = format!("{}:{}:{}:{}", timestamp, method, path, body);

        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .map_err(|e| CreditError::HmacError(format!("Failed to create HMAC: {}", e)))?;

        mac.update(message.as_bytes());

        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        Ok(hex::encode(code_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_generation() -> Result<(), Box<dyn std::error::Error>> {
        let test_key = vec![0x42; 32];
        let timestamp = "1234567890";
        let method = "POST";
        let path = "/v1/credits/consume";
        let body = r#"{"customer_id":"test"}"#;

        let message = format!("{}:{}:{}:{}", timestamp, method, path, body);
        let mut mac = HmacSha256::new_from_slice(&test_key)?;
        mac.update(message.as_bytes());
        let result = mac.finalize();
        let signature = hex::encode(result.into_bytes());

        assert_eq!(signature.len(), 64);
        Ok(())
    }

    #[test]
    fn test_hmac_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let test_key = vec![0x42; 32];
        let timestamp = "1234567890";
        let method = "POST";
        let path = "/v1/credits/consume";
        let body = r#"{"customer_id":"test"}"#;

        let message = format!("{}:{}:{}:{}", timestamp, method, path, body);

        let mut mac1 = HmacSha256::new_from_slice(&test_key)?;
        mac1.update(message.as_bytes());
        let sig1 = hex::encode(mac1.finalize().into_bytes());

        let mut mac2 = HmacSha256::new_from_slice(&test_key)?;
        mac2.update(message.as_bytes());
        let sig2 = hex::encode(mac2.finalize().into_bytes());

        assert_eq!(sig1, sig2, "HMAC should be deterministic");
        Ok(())
    }

    #[test]
    fn test_hmac_different_timestamps() -> Result<(), Box<dyn std::error::Error>> {
        let test_key = vec![0x42; 32];
        let method = "POST";
        let path = "/v1/credits/consume";
        let body = r#"{"customer_id":"test"}"#;

        let message1 = format!("{}:{}:{}:{}", "1234567890", method, path, body);
        let mut mac1 = HmacSha256::new_from_slice(&test_key)?;
        mac1.update(message1.as_bytes());
        let sig1 = hex::encode(mac1.finalize().into_bytes());

        let message2 = format!("{}:{}:{}:{}", "1234567891", method, path, body);
        let mut mac2 = HmacSha256::new_from_slice(&test_key)?;
        mac2.update(message2.as_bytes());
        let sig2 = hex::encode(mac2.finalize().into_bytes());

        assert_ne!(
            sig1, sig2,
            "Different timestamps should produce different signatures"
        );
        Ok(())
    }

    #[test]
    fn test_consume_credits_body_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let body = ConsumeCreditsBody {
            customer_id: "customer-123".to_string(),
            verification_id: "ver-456".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: Some("issuer-789".to_string()),
            environment: Some("sandbox".to_string()),
        };

        let json = serde_json::to_string(&body)?;
        assert!(json.contains("customer-123"));
        assert!(json.contains("ver-456"));
        assert!(json.contains("issuer-789"));
        assert!(json.contains("sandbox"));
        // Auth fields must NOT appear in the body (they belong in headers)
        assert!(!json.contains("timestamp"));
        assert!(!json.contains("hmac"));
        Ok(())
    }

    #[test]
    fn test_consume_credits_body_optional_fields() -> Result<(), Box<dyn std::error::Error>> {
        let body = ConsumeCreditsBody {
            customer_id: "customer-123".to_string(),
            verification_id: "ver-456".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: None,
            environment: None,
        };

        let json = serde_json::to_string(&body)?;
        assert!(json.contains("customer-123"));
        assert!(json.contains("ver-456"));
        assert!(!json.contains("issuer_kid"));
        assert!(!json.contains("environment"));
        assert!(!json.contains("timestamp"));
        assert!(!json.contains("hmac"));
        Ok(())
    }

    #[test]
    fn test_error_response_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"error":"Insufficient credits","code":"INSUFFICIENT_CREDITS","available":50,"required":100}"#;
        let response: ErrorResponse = serde_json::from_str(json)?;

        assert_eq!(response.error, "Insufficient credits");
        assert_eq!(response.code, Some("INSUFFICIENT_CREDITS".to_string()));
        assert_eq!(response.available, Some(50));
        assert_eq!(response.required, Some(100));
        Ok(())
    }

    #[test]
    fn test_consume_credits_response_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"success":true,"transaction_id":"tx-1","balance_after_units":150,"royalty_units_credited":10}"#;
        let response: ConsumeCreditsResponse = serde_json::from_str(json)?;

        assert_eq!(response.balance_after_units, Some(150));
        assert_eq!(response.royalty_units_credited, Some(10));
        Ok(())
    }

    #[test]
    fn test_consume_credits_response_missing_optional_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"success":true}"#;
        let response: ConsumeCreditsResponse = serde_json::from_str(json)?;

        assert_eq!(response.balance_after_units, None);
        assert_eq!(response.royalty_units_credited, None);
        Ok(())
    }

    // ======================================================================
    // CreditError Display coverage
    // ======================================================================

    #[test]
    fn test_credit_error_insufficient_credits_display() {
        let err = CreditError::InsufficientCredits {
            required: 100,
            available: 50,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
        assert!(msg.contains("Insufficient credits"));
    }

    #[test]
    fn test_credit_error_service_unavailable_display() {
        let err = CreditError::ServiceUnavailable;
        assert_eq!(format!("{}", err), "Credit service unavailable");
    }

    #[test]
    fn test_credit_error_conflict_display() {
        let err = CreditError::Conflict("duplicate transaction".to_string());
        assert!(format!("{}", err).contains("duplicate transaction"));
    }

    #[test]
    fn test_credit_error_invalid_request_display() {
        let err = CreditError::InvalidRequest("bad field".to_string());
        assert!(format!("{}", err).contains("bad field"));
    }

    #[test]
    fn test_credit_error_network_error_display() {
        let err = CreditError::NetworkError("timeout".to_string());
        assert!(format!("{}", err).contains("timeout"));
    }

    #[test]
    fn test_credit_error_serialization_error_display() {
        let err = CreditError::SerializationError("invalid json".to_string());
        assert!(format!("{}", err).contains("invalid json"));
    }

    #[test]
    fn test_credit_error_hmac_error_display() {
        let err = CreditError::HmacError("key too short".to_string());
        assert!(format!("{}", err).contains("key too short"));
    }

    #[test]
    fn test_credit_error_ssrf_error_display() {
        let err = CreditError::SsrfError("blocked redirect".to_string());
        assert!(format!("{}", err).contains("blocked redirect"));
    }

    // ======================================================================
    // HMAC canonical message format
    // ======================================================================

    #[test]
    fn test_hmac_canonical_message_format() {
        let timestamp = "1234567890";
        let method = "POST";
        let path = "/v1/credits/consume";
        let body = r#"{"customer_id":"test"}"#;

        let message = format!("{}:{}:{}:{}", timestamp, method, path, body);
        assert_eq!(
            message,
            r#"1234567890:POST:/v1/credits/consume:{"customer_id":"test"}"#
        );
    }

    #[test]
    fn test_hmac_different_bodies_produce_different_signatures(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_key = vec![0x42; 32];
        let timestamp = "1234567890";
        let method = "POST";
        let path = "/v1/credits/consume";

        let msg1 = format!("{}:{}:{}:{}", timestamp, method, path, r#"{"a":1}"#);
        let mut mac1 = HmacSha256::new_from_slice(&test_key)?;
        mac1.update(msg1.as_bytes());
        let sig1 = hex::encode(mac1.finalize().into_bytes());

        let msg2 = format!("{}:{}:{}:{}", timestamp, method, path, r#"{"a":2}"#);
        let mut mac2 = HmacSha256::new_from_slice(&test_key)?;
        mac2.update(msg2.as_bytes());
        let sig2 = hex::encode(mac2.finalize().into_bytes());

        assert_ne!(sig1, sig2);
        Ok(())
    }

    #[test]
    fn test_hmac_different_keys_produce_different_signatures(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key1 = vec![0x42; 32];
        let key2 = vec![0x43; 32];
        let message = "1234567890:POST:/v1/credits/consume:{}";

        let mut mac1 = HmacSha256::new_from_slice(&key1)?;
        mac1.update(message.as_bytes());
        let sig1 = hex::encode(mac1.finalize().into_bytes());

        let mut mac2 = HmacSha256::new_from_slice(&key2)?;
        mac2.update(message.as_bytes());
        let sig2 = hex::encode(mac2.finalize().into_bytes());

        assert_ne!(sig1, sig2);
        Ok(())
    }

    #[test]
    fn test_hmac_signature_is_64_hex_chars() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0xAB; 32];
        let message = "test message";
        let mut mac = HmacSha256::new_from_slice(&key)?;
        mac.update(message.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    // ======================================================================
    // ConsumeCreditsBody serialisation edge cases
    // ======================================================================

    #[test]
    fn test_consume_credits_body_production_environment() -> Result<(), Box<dyn std::error::Error>>
    {
        // Production environment is serialised as None (not included)
        let body = ConsumeCreditsBody {
            customer_id: "c1".to_string(),
            verification_id: "v1".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: None,
            environment: None,
        };
        let json = serde_json::to_string(&body)?;
        assert!(!json.contains("environment"));
        Ok(())
    }

    #[test]
    fn test_consume_credits_body_sandbox_environment() -> Result<(), Box<dyn std::error::Error>> {
        let body = ConsumeCreditsBody {
            customer_id: "c1".to_string(),
            verification_id: "v1".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: None,
            environment: Some("sandbox".to_string()),
        };
        let json = serde_json::to_string(&body)?;
        assert!(json.contains("sandbox"));
        Ok(())
    }

    #[test]
    fn test_consume_credits_body_all_fields_present() -> Result<(), Box<dyn std::error::Error>> {
        let body = ConsumeCreditsBody {
            customer_id: "c1".to_string(),
            verification_id: "v1".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: Some("ik1".to_string()),
            environment: Some("sandbox".to_string()),
        };
        let json = serde_json::to_string(&body)?;
        assert!(json.contains("c1"));
        assert!(json.contains("v1"));
        assert!(json.contains("https://example.com"));
        assert!(json.contains("ik1"));
        assert!(json.contains("sandbox"));
        Ok(())
    }

    // ======================================================================
    // ErrorResponse deserialisation edge cases
    // ======================================================================

    #[test]
    fn test_error_response_minimal_fields() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"error":"Something went wrong"}"#;
        let response: ErrorResponse = serde_json::from_str(json)?;
        assert_eq!(response.error, "Something went wrong");
        assert!(response.code.is_none());
        assert!(response.available.is_none());
        assert!(response.required.is_none());
        Ok(())
    }

    #[test]
    fn test_error_response_all_fields() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"error":"fail","code":"ERR_X","available":0,"required":10}"#;
        let response: ErrorResponse = serde_json::from_str(json)?;
        assert_eq!(response.error, "fail");
        assert_eq!(response.code, Some("ERR_X".to_string()));
        assert_eq!(response.available, Some(0));
        assert_eq!(response.required, Some(10));
        Ok(())
    }

    #[test]
    fn test_error_response_unknown_fields_ignored() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"error":"x","extra_field":"ignored"}"#;
        let response: ErrorResponse = serde_json::from_str(json)?;
        assert_eq!(response.error, "x");
        Ok(())
    }

    // ======================================================================
    // ConsumeCreditsResponse edge cases
    // ======================================================================

    #[test]
    fn test_consume_credits_response_zero_balance() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"balance_after_units":0}"#;
        let response: ConsumeCreditsResponse = serde_json::from_str(json)?;
        assert_eq!(response.balance_after_units, Some(0));
        Ok(())
    }

    #[test]
    fn test_consume_credits_response_large_values() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"balance_after_units":999999999,"royalty_units_credited":100000}"#;
        let response: ConsumeCreditsResponse = serde_json::from_str(json)?;
        assert_eq!(response.balance_after_units, Some(999_999_999));
        assert_eq!(response.royalty_units_credited, Some(100_000));
        Ok(())
    }

    #[test]
    fn test_consume_credits_response_unknown_fields_ignored(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"balance_after_units":10,"future_field":"ignored"}"#;
        let response: ConsumeCreditsResponse = serde_json::from_str(json)?;
        assert_eq!(response.balance_after_units, Some(10));
        Ok(())
    }

    // ======================================================================
    // ConsumeCreditsRequest fields
    // ======================================================================

    #[test]
    fn test_consume_credits_request_clone() {
        let req = ConsumeCreditsRequest {
            customer_id: "c1".to_string(),
            verification_id: "v1".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: Some("ik1".to_string()),
            environment: "production".to_string(),
            partner_id: Some("partner_x".to_string()),
        };
        let cloned = req.clone();
        assert_eq!(cloned.customer_id, "c1");
        assert_eq!(cloned.partner_id, Some("partner_x".to_string()));
    }

    #[test]
    fn test_consume_credits_request_debug_redaction() {
        let req = ConsumeCreditsRequest {
            customer_id: "c1".to_string(),
            verification_id: "v1".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: None,
            environment: "sandbox".to_string(),
            partner_id: None,
        };
        let dbg = format!("{:?}", req);
        assert!(dbg.contains("c1"));
        assert!(dbg.contains("v1"));
    }

    // ======================================================================
    // Constants
    // ======================================================================

    #[test]
    fn test_max_retries_constant() {
        assert_eq!(MAX_RETRIES, 3);
        assert!(MAX_RETRIES > 0);
    }

    #[test]
    fn test_initial_backoff_constant() {
        assert_eq!(INITIAL_BACKOFF_MS, 100);
        assert!(INITIAL_BACKOFF_MS > 0);
    }

    // ======================================================================
    // HMAC edge cases
    // ======================================================================

    #[test]
    fn test_hmac_empty_body() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0x42; 32];
        let message = format!("{}:{}:{}:{}", "1000", "POST", "/v1/credits/consume", "");
        let mut mac = HmacSha256::new_from_slice(&key)?;
        mac.update(message.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn test_hmac_empty_timestamp() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0x42; 32];
        let message = format!("{}:{}:{}:{}", "", "POST", "/v1/credits/consume", "{}");
        let mut mac = HmacSha256::new_from_slice(&key)?;
        mac.update(message.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig.len(), 64);
        Ok(())
    }

    #[test]
    fn test_hmac_empty_method() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0x42; 32];
        let message = format!("{}:{}:{}:{}", "1000", "", "/path", "body");
        let mut mac = HmacSha256::new_from_slice(&key)?;
        mac.update(message.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig.len(), 64);
        Ok(())
    }

    #[test]
    fn test_hmac_empty_path() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0x42; 32];
        let message = format!("{}:{}:{}:{}", "1000", "POST", "", "body");
        let mut mac = HmacSha256::new_from_slice(&key)?;
        mac.update(message.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig.len(), 64);
        Ok(())
    }

    #[test]
    fn test_hmac_short_key() -> Result<(), Box<dyn std::error::Error>> {
        // HMAC-SHA256 accepts keys of any length (short keys are zero-padded internally)
        let key = vec![0x01; 1];
        let message = "ts:POST:/path:body";
        let mut mac = HmacSha256::new_from_slice(&key)?;
        mac.update(message.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig.len(), 64);
        Ok(())
    }

    #[test]
    fn test_hmac_long_key() -> Result<(), Box<dyn std::error::Error>> {
        // HMAC-SHA256 hashes keys longer than the block size (64 bytes)
        let key = vec![0xAA; 128];
        let message = "ts:POST:/path:body";
        let mut mac = HmacSha256::new_from_slice(&key)?;
        mac.update(message.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig.len(), 64);
        Ok(())
    }

    #[test]
    fn test_hmac_known_test_vector() -> Result<(), Box<dyn std::error::Error>> {
        // RFC 4231 Test Case 2: "what do ya want for nothing?" with key "Jefe"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mut mac = HmacSha256::new_from_slice(key)?;
        mac.update(data);
        let sig = hex::encode(mac.finalize().into_bytes());
        assert_eq!(
            sig,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        Ok(())
    }

    #[test]
    fn test_hmac_different_methods_produce_different_signatures(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0x42; 32];
        let ts = "1000";
        let path = "/v1/credits/consume";
        let body = "{}";

        let msg_post = format!("{}:{}:{}:{}", ts, "POST", path, body);
        let mut mac1 = HmacSha256::new_from_slice(&key)?;
        mac1.update(msg_post.as_bytes());
        let sig_post = hex::encode(mac1.finalize().into_bytes());

        let msg_get = format!("{}:{}:{}:{}", ts, "GET", path, body);
        let mut mac2 = HmacSha256::new_from_slice(&key)?;
        mac2.update(msg_get.as_bytes());
        let sig_get = hex::encode(mac2.finalize().into_bytes());

        assert_ne!(
            sig_post, sig_get,
            "Different methods should produce different signatures"
        );
        Ok(())
    }

    #[test]
    fn test_hmac_different_paths_produce_different_signatures(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0x42; 32];
        let ts = "1000";
        let body = "{}";

        let msg1 = format!("{}:{}:{}:{}", ts, "POST", "/v1/credits/consume", body);
        let mut mac1 = HmacSha256::new_from_slice(&key)?;
        mac1.update(msg1.as_bytes());
        let sig1 = hex::encode(mac1.finalize().into_bytes());

        let msg2 = format!("{}:{}:{}:{}", ts, "POST", "/v1/credits/refund", body);
        let mut mac2 = HmacSha256::new_from_slice(&key)?;
        mac2.update(msg2.as_bytes());
        let sig2 = hex::encode(mac2.finalize().into_bytes());

        assert_ne!(
            sig1, sig2,
            "Different paths should produce different signatures"
        );
        Ok(())
    }

    #[test]
    fn test_hmac_canonical_message_all_empty() {
        let message = format!("{}:{}:{}:{}", "", "", "", "");
        assert_eq!(message, ":::");
    }

    #[test]
    fn test_hmac_canonical_message_with_colons_in_body() {
        // Body containing colons should not break the canonical format
        let message = format!(
            "{}:{}:{}:{}",
            "1000", "POST", "/path", r#"{"url":"https://example.com:443"}"#
        );
        // The canonical format uses the first 3 colons as delimiters;
        // everything after the 3rd colon is the body.
        assert!(message.starts_with("1000:POST:/path:"));
    }

    // ======================================================================
    // Hex decode error path
    // ======================================================================

    #[test]
    fn test_hex_decode_invalid_hex_string() {
        let result = hex::decode("not-valid-hex!");
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_decode_odd_length() {
        let result = hex::decode("abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_decode_valid() -> Result<(), Box<dyn std::error::Error>> {
        let bytes =
            hex::decode("4242424242424242424242424242424242424242424242424242424242424242")?;
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().all(|&b| b == 0x42));
        Ok(())
    }

    #[test]
    fn test_hex_decode_empty_string() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = hex::decode("")?;
        assert!(bytes.is_empty());
        Ok(())
    }

    // ======================================================================
    // HMAC key decoding: base64url-no-pad standard + legacy hex fallback
    // ======================================================================

    #[test]
    fn test_decode_hmac_key_base64url_standard() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let raw = [0x42u8; 32];
        let encoded = URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(
            encoded.len(),
            43,
            "base64url-no-pad of 32 bytes is 43 chars"
        );
        let bytes = CreditManagementClient::decode_hmac_key(&encoded)?;
        assert_eq!(bytes, raw);
        Ok(())
    }

    #[test]
    fn test_decode_hmac_key_legacy_hex() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = CreditManagementClient::decode_hmac_key(
            "4242424242424242424242424242424242424242424242424242424242424242",
        )?;
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().all(|&b| b == 0x42));
        Ok(())
    }

    #[test]
    fn test_decode_hmac_key_invalid_base64url_errors() {
        // 43 chars but contains a non-base64url character ('!').
        let bad = format!("{}!", "A".repeat(42));
        assert_eq!(bad.len(), 43);
        assert!(CreditManagementClient::decode_hmac_key(&bad).is_err());
    }

    // ======================================================================
    // ConsumeCreditsBody JSON structure verification
    // ======================================================================

    #[test]
    fn test_consume_credits_body_field_names_match_zod_schema(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let body = ConsumeCreditsBody {
            customer_id: "cust".to_string(),
            verification_id: "ver".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: Some("kid".to_string()),
            environment: Some("sandbox".to_string()),
        };
        let json = serde_json::to_string(&body)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        let obj = parsed.as_object().ok_or("expected object")?;

        // Verify exact field names (must match provii-credit-management Zod schema)
        assert!(obj.contains_key("customer_id"));
        assert!(obj.contains_key("verification_id"));
        assert!(obj.contains_key("origin"));
        assert!(obj.contains_key("issuer_kid"));
        assert!(obj.contains_key("environment"));
        // Must NOT contain auth fields
        assert!(!obj.contains_key("timestamp"));
        assert!(!obj.contains_key("hmac"));
        assert!(!obj.contains_key("nonce"));
        assert!(!obj.contains_key("api_key_id"));
        assert!(!obj.contains_key("partner_id"));
        Ok(())
    }

    #[test]
    fn test_consume_credits_body_none_fields_omitted_from_json(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let body = ConsumeCreditsBody {
            customer_id: "c".to_string(),
            verification_id: "v".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: None,
            environment: None,
        };
        let json = serde_json::to_string(&body)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        let obj = parsed.as_object().ok_or("expected object")?;

        // Only required fields present
        assert_eq!(obj.len(), 3);
        assert!(obj.contains_key("customer_id"));
        assert!(obj.contains_key("verification_id"));
        assert!(obj.contains_key("origin"));
        Ok(())
    }

    #[test]
    fn test_consume_credits_body_special_characters_in_origin(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let body = ConsumeCreditsBody {
            customer_id: "c".to_string(),
            verification_id: "v".to_string(),
            origin: "https://example.com/path?query=1&foo=bar#fragment".to_string(),
            issuer_kid: None,
            environment: None,
        };
        let json = serde_json::to_string(&body)?;
        // Round-trip: verify JSON encodes and can be re-parsed
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(
            parsed["origin"],
            "https://example.com/path?query=1&foo=bar#fragment"
        );
        Ok(())
    }

    #[test]
    fn test_consume_credits_body_unicode_in_fields() -> Result<(), Box<dyn std::error::Error>> {
        let body = ConsumeCreditsBody {
            customer_id: "cust-\u{00E9}\u{00E8}".to_string(),
            verification_id: "v".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: None,
            environment: None,
        };
        let json = serde_json::to_string(&body)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert!(parsed["customer_id"]
            .as_str()
            .ok_or("not a string")?
            .contains('\u{00E9}'));
        Ok(())
    }

    #[test]
    fn test_consume_credits_body_empty_strings() -> Result<(), Box<dyn std::error::Error>> {
        let body = ConsumeCreditsBody {
            customer_id: "".to_string(),
            verification_id: "".to_string(),
            origin: "".to_string(),
            issuer_kid: Some("".to_string()),
            environment: Some("".to_string()),
        };
        let json = serde_json::to_string(&body)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["customer_id"], "");
        assert_eq!(parsed["verification_id"], "");
        assert_eq!(parsed["origin"], "");
        assert_eq!(parsed["issuer_kid"], "");
        assert_eq!(parsed["environment"], "");
        Ok(())
    }

    // ======================================================================
    // ErrorResponse edge cases
    // ======================================================================

    #[test]
    fn test_error_response_zero_available_and_required() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"error":"no credits","available":0,"required":0}"#;
        let response: ErrorResponse = serde_json::from_str(json)?;
        assert_eq!(response.available, Some(0));
        assert_eq!(response.required, Some(0));
        Ok(())
    }

    #[test]
    fn test_error_response_large_values() -> Result<(), Box<dyn std::error::Error>> {
        let json =
            r#"{"error":"fail","available":18446744073709551615,"required":18446744073709551615}"#;
        let response: ErrorResponse = serde_json::from_str(json)?;
        assert_eq!(response.available, Some(u64::MAX));
        assert_eq!(response.required, Some(u64::MAX));
        Ok(())
    }

    #[test]
    fn test_error_response_only_code_present() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"error":"whoops","code":"SOME_CODE"}"#;
        let response: ErrorResponse = serde_json::from_str(json)?;
        assert_eq!(response.code, Some("SOME_CODE".to_string()));
        assert!(response.available.is_none());
        assert!(response.required.is_none());
        Ok(())
    }

    #[test]
    fn test_error_response_only_available_present() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"error":"fail","available":42}"#;
        let response: ErrorResponse = serde_json::from_str(json)?;
        assert_eq!(response.available, Some(42));
        assert!(response.code.is_none());
        assert!(response.required.is_none());
        Ok(())
    }

    #[test]
    fn test_error_response_only_required_present() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"error":"fail","required":5}"#;
        let response: ErrorResponse = serde_json::from_str(json)?;
        assert_eq!(response.required, Some(5));
        assert!(response.code.is_none());
        assert!(response.available.is_none());
        Ok(())
    }

    #[test]
    fn test_error_response_empty_error_string() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"error":""}"#;
        let response: ErrorResponse = serde_json::from_str(json)?;
        assert_eq!(response.error, "");
        Ok(())
    }

    #[test]
    fn test_error_response_missing_error_field_fails() {
        let json = r#"{"code":"SOME_CODE"}"#;
        let result = serde_json::from_str::<ErrorResponse>(json);
        assert!(result.is_err(), "error field is required");
    }

    #[test]
    fn test_error_response_null_optional_fields() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"error":"fail","code":null,"available":null,"required":null}"#;
        let response: ErrorResponse = serde_json::from_str(json)?;
        assert!(response.code.is_none());
        assert!(response.available.is_none());
        assert!(response.required.is_none());
        Ok(())
    }

    #[test]
    fn test_error_response_clone() {
        let response = ErrorResponse {
            error: "test error".to_string(),
            code: Some("CODE".to_string()),
            available: Some(10),
            required: Some(20),
        };
        let cloned = response.clone();
        assert_eq!(cloned.error, response.error);
        assert_eq!(cloned.code, response.code);
        assert_eq!(cloned.available, response.available);
        assert_eq!(cloned.required, response.required);
    }

    #[test]
    fn test_error_response_debug() {
        let response = ErrorResponse {
            error: "test".to_string(),
            code: None,
            available: None,
            required: None,
        };
        let dbg = format!("{:?}", response);
        assert!(dbg.contains("ErrorResponse"));
        assert!(dbg.contains("test"));
    }

    // ======================================================================
    // ConsumeCreditsResponse edge cases
    // ======================================================================

    #[test]
    fn test_consume_credits_response_only_royalty() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"royalty_units_credited":5}"#;
        let response: ConsumeCreditsResponse = serde_json::from_str(json)?;
        assert!(response.balance_after_units.is_none());
        assert_eq!(response.royalty_units_credited, Some(5));
        Ok(())
    }

    #[test]
    fn test_consume_credits_response_only_balance() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"balance_after_units":42}"#;
        let response: ConsumeCreditsResponse = serde_json::from_str(json)?;
        assert_eq!(response.balance_after_units, Some(42));
        assert!(response.royalty_units_credited.is_none());
        Ok(())
    }

    #[test]
    fn test_consume_credits_response_u64_max() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"balance_after_units":18446744073709551615}"#;
        let response: ConsumeCreditsResponse = serde_json::from_str(json)?;
        assert_eq!(response.balance_after_units, Some(u64::MAX));
        Ok(())
    }

    #[test]
    fn test_consume_credits_response_empty_object() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{}"#;
        let response: ConsumeCreditsResponse = serde_json::from_str(json)?;
        assert!(response.balance_after_units.is_none());
        assert!(response.royalty_units_credited.is_none());
        Ok(())
    }

    #[test]
    fn test_consume_credits_response_null_fields() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"balance_after_units":null,"royalty_units_credited":null}"#;
        let response: ConsumeCreditsResponse = serde_json::from_str(json)?;
        assert!(response.balance_after_units.is_none());
        assert!(response.royalty_units_credited.is_none());
        Ok(())
    }

    #[test]
    fn test_consume_credits_response_invalid_json_fails() {
        let result = serde_json::from_str::<ConsumeCreditsResponse>("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_consume_credits_response_negative_value_fails() {
        // u64 cannot hold negative values
        let json = r#"{"balance_after_units":-1}"#;
        let result = serde_json::from_str::<ConsumeCreditsResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_consume_credits_response_clone() {
        let response = ConsumeCreditsResponse {
            balance_after_units: Some(100),
            royalty_units_credited: Some(10),
        };
        let cloned = response.clone();
        assert_eq!(cloned.balance_after_units, response.balance_after_units);
        assert_eq!(
            cloned.royalty_units_credited,
            response.royalty_units_credited
        );
    }

    #[test]
    fn test_consume_credits_response_debug() {
        let response = ConsumeCreditsResponse {
            balance_after_units: Some(99),
            royalty_units_credited: None,
        };
        let dbg = format!("{:?}", response);
        assert!(dbg.contains("ConsumeCreditsResponse"));
        assert!(dbg.contains("99"));
    }

    // ======================================================================
    // ConsumeCreditsRequest edge cases
    // ======================================================================

    #[test]
    fn test_consume_credits_request_all_none_optionals() {
        let req = ConsumeCreditsRequest {
            customer_id: "c".to_string(),
            verification_id: "v".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: None,
            environment: "production".to_string(),
            partner_id: None,
        };
        assert!(req.issuer_kid.is_none());
        assert!(req.partner_id.is_none());
    }

    #[test]
    fn test_consume_credits_request_debug_contains_all_field_names() {
        let req = ConsumeCreditsRequest {
            customer_id: "c1".to_string(),
            verification_id: "v1".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: Some("kid1".to_string()),
            environment: "sandbox".to_string(),
            partner_id: Some("p1".to_string()),
        };
        let dbg = format!("{:?}", req);
        assert!(dbg.contains("customer_id"));
        assert!(dbg.contains("verification_id"));
        assert!(dbg.contains("origin"));
        assert!(dbg.contains("issuer_kid"));
        assert!(dbg.contains("environment"));
        assert!(dbg.contains("partner_id"));
        assert!(dbg.contains("kid1"));
        assert!(dbg.contains("p1"));
    }

    #[test]
    fn test_consume_credits_request_clone_independence() {
        let req = ConsumeCreditsRequest {
            customer_id: "c".to_string(),
            verification_id: "v".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: Some("k".to_string()),
            environment: "sandbox".to_string(),
            partner_id: Some("p".to_string()),
        };
        let mut cloned = req.clone();
        cloned.customer_id = "different".to_string();
        // Original should be unchanged
        assert_eq!(req.customer_id, "c");
        assert_eq!(cloned.customer_id, "different");
    }

    // ======================================================================
    // CreditError Debug formatting
    // ======================================================================

    #[test]
    fn test_credit_error_insufficient_credits_debug() {
        let err = CreditError::InsufficientCredits {
            required: 100,
            available: 50,
        };
        let dbg = format!("{:?}", err);
        assert!(dbg.contains("InsufficientCredits"));
        assert!(dbg.contains("100"));
        assert!(dbg.contains("50"));
    }

    #[test]
    fn test_credit_error_service_unavailable_debug() {
        let err = CreditError::ServiceUnavailable;
        let dbg = format!("{:?}", err);
        assert!(dbg.contains("ServiceUnavailable"));
    }

    #[test]
    fn test_credit_error_conflict_debug() {
        let err = CreditError::Conflict("dup".to_string());
        let dbg = format!("{:?}", err);
        assert!(dbg.contains("Conflict"));
        assert!(dbg.contains("dup"));
    }

    #[test]
    fn test_credit_error_invalid_request_debug() {
        let err = CreditError::InvalidRequest("bad".to_string());
        let dbg = format!("{:?}", err);
        assert!(dbg.contains("InvalidRequest"));
        assert!(dbg.contains("bad"));
    }

    #[test]
    fn test_credit_error_network_error_debug() {
        let err = CreditError::NetworkError("conn refused".to_string());
        let dbg = format!("{:?}", err);
        assert!(dbg.contains("NetworkError"));
        assert!(dbg.contains("conn refused"));
    }

    #[test]
    fn test_credit_error_serialization_error_debug() {
        let err = CreditError::SerializationError("parse fail".to_string());
        let dbg = format!("{:?}", err);
        assert!(dbg.contains("SerializationError"));
        assert!(dbg.contains("parse fail"));
    }

    #[test]
    fn test_credit_error_hmac_error_debug() {
        let err = CreditError::HmacError("invalid key".to_string());
        let dbg = format!("{:?}", err);
        assert!(dbg.contains("HmacError"));
        assert!(dbg.contains("invalid key"));
    }

    #[test]
    fn test_credit_error_ssrf_error_debug() {
        let err = CreditError::SsrfError("redirect blocked".to_string());
        let dbg = format!("{:?}", err);
        assert!(dbg.contains("SsrfError"));
        assert!(dbg.contains("redirect blocked"));
    }

    // ======================================================================
    // CreditError Display with empty strings
    // ======================================================================

    #[test]
    fn test_credit_error_conflict_empty_message() {
        let err = CreditError::Conflict("".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Conflict"));
    }

    #[test]
    fn test_credit_error_network_error_empty_message() {
        let err = CreditError::NetworkError("".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Network error"));
    }

    #[test]
    fn test_credit_error_hmac_error_empty_message() {
        let err = CreditError::HmacError("".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("HMAC signature error"));
    }

    #[test]
    fn test_credit_error_ssrf_error_empty_message() {
        let err = CreditError::SsrfError("".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("SSRF validation error"));
    }

    #[test]
    fn test_credit_error_serialization_error_empty_message() {
        let err = CreditError::SerializationError("".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Serialization error"));
    }

    #[test]
    fn test_credit_error_invalid_request_empty_message() {
        let err = CreditError::InvalidRequest("".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid request"));
    }

    #[test]
    fn test_credit_error_insufficient_credits_zero_values() {
        let err = CreditError::InsufficientCredits {
            required: 0,
            available: 0,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("0 required"));
        assert!(msg.contains("0 available"));
    }

    #[test]
    fn test_credit_error_insufficient_credits_large_values() {
        let err = CreditError::InsufficientCredits {
            required: u64::MAX,
            available: u64::MAX,
        };
        let msg = format!("{}", err);
        assert!(msg.contains(&u64::MAX.to_string()));
    }

    // ======================================================================
    // Backoff arithmetic
    // ======================================================================

    #[test]
    fn test_backoff_doubling_sequence() {
        let mut backoff = INITIAL_BACKOFF_MS;
        assert_eq!(backoff, 100);
        backoff = backoff.saturating_mul(2);
        assert_eq!(backoff, 200);
        backoff = backoff.saturating_mul(2);
        assert_eq!(backoff, 400);
    }

    #[test]
    fn test_backoff_saturating_mul_no_overflow() {
        let backoff: u64 = u64::MAX;
        let doubled = backoff.saturating_mul(2);
        assert_eq!(doubled, u64::MAX, "saturating_mul should cap at u64::MAX");
    }

    #[test]
    fn test_backoff_saturating_mul_near_max() {
        let backoff: u64 = u64::MAX / 2 + 1;
        let doubled = backoff.saturating_mul(2);
        assert_eq!(doubled, u64::MAX);
    }

    #[test]
    fn test_retry_count_bounds() {
        // Verify the retry loop range: 1..=MAX_RETRIES means exactly MAX_RETRIES attempts
        let attempts: Vec<usize> = (1..=MAX_RETRIES).collect();
        assert_eq!(attempts.len(), 3);
        assert_eq!(attempts[0], 1);
        assert_eq!(attempts[2], 3);
    }

    // ======================================================================
    // ConsumeCreditsBody serialisation round-trip
    // ======================================================================

    #[test]
    fn test_consume_credits_body_json_round_trip_full() -> Result<(), Box<dyn std::error::Error>> {
        let body = ConsumeCreditsBody {
            customer_id: "cust-abc".to_string(),
            verification_id: "ver-xyz".to_string(),
            origin: "https://example.com".to_string(),
            issuer_kid: Some("ik-123".to_string()),
            environment: Some("sandbox".to_string()),
        };
        let json = serde_json::to_string(&body)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;

        assert_eq!(parsed["customer_id"], "cust-abc");
        assert_eq!(parsed["verification_id"], "ver-xyz");
        assert_eq!(parsed["origin"], "https://example.com");
        assert_eq!(parsed["issuer_kid"], "ik-123");
        assert_eq!(parsed["environment"], "sandbox");
        Ok(())
    }

    #[test]
    fn test_consume_credits_body_json_round_trip_minimal() -> Result<(), Box<dyn std::error::Error>>
    {
        let body = ConsumeCreditsBody {
            customer_id: "c".to_string(),
            verification_id: "v".to_string(),
            origin: "o".to_string(),
            issuer_kid: None,
            environment: None,
        };
        let json = serde_json::to_string(&body)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;

        assert_eq!(parsed["customer_id"], "c");
        assert_eq!(parsed["verification_id"], "v");
        assert_eq!(parsed["origin"], "o");
        assert!(parsed.get("issuer_kid").is_none());
        assert!(parsed.get("environment").is_none());
        Ok(())
    }

    // ======================================================================
    // Zeroizing wrapper behaviour
    // ======================================================================

    #[test]
    fn test_zeroizing_vec_drop_does_not_panic() {
        // Verify Zeroizing<Vec<u8>> can be created and dropped without panicking
        let data = Zeroizing::new(vec![0x42u8; 32]);
        assert_eq!(data.len(), 32);
        drop(data);
    }

    #[test]
    fn test_zeroizing_string_drop_does_not_panic() {
        let data = Zeroizing::new("secret_hex_key".to_string());
        assert_eq!(data.len(), 14);
        drop(data);
    }

    // ======================================================================
    // ConsumeCreditsBody Clone and Debug
    // ======================================================================

    #[test]
    fn test_consume_credits_body_clone() {
        let body = ConsumeCreditsBody {
            customer_id: "c".to_string(),
            verification_id: "v".to_string(),
            origin: "o".to_string(),
            issuer_kid: Some("k".to_string()),
            environment: Some("sandbox".to_string()),
        };
        let cloned = body.clone();
        assert_eq!(cloned.customer_id, "c");
        assert_eq!(cloned.issuer_kid, Some("k".to_string()));
    }

    #[test]
    fn test_consume_credits_body_debug() {
        let body = ConsumeCreditsBody {
            customer_id: "c".to_string(),
            verification_id: "v".to_string(),
            origin: "o".to_string(),
            issuer_kid: None,
            environment: None,
        };
        let dbg = format!("{:?}", body);
        assert!(dbg.contains("ConsumeCreditsBody"));
        assert!(dbg.contains("customer_id"));
    }

    // ======================================================================
    // HmacSha256 type alias verification
    // ======================================================================

    #[test]
    fn test_hmac_sha256_output_is_32_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0x00; 32];
        let mut mac = HmacSha256::new_from_slice(&key)?;
        mac.update(b"data");
        let result = mac.finalize();
        let bytes = result.into_bytes();
        // SHA-256 produces 32 bytes = 256 bits
        assert_eq!(bytes.len(), 32);
        Ok(())
    }

    // ======================================================================
    // ErrorResponse deserialisation with wrong types
    // ======================================================================

    #[test]
    fn test_error_response_string_available_fails() {
        let json = r#"{"error":"fail","available":"not_a_number"}"#;
        let result = serde_json::from_str::<ErrorResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_response_string_required_fails() {
        let json = r#"{"error":"fail","required":"not_a_number"}"#;
        let result = serde_json::from_str::<ErrorResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_response_boolean_code_fails() {
        let json = r#"{"error":"fail","code":true}"#;
        let result = serde_json::from_str::<ErrorResponse>(json);
        assert!(result.is_err());
    }

    // ======================================================================
    // ConsumeCreditsResponse deserialisation with wrong types
    // ======================================================================

    #[test]
    fn test_consume_credits_response_string_balance_fails() {
        let json = r#"{"balance_after_units":"not_a_number"}"#;
        let result = serde_json::from_str::<ConsumeCreditsResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_consume_credits_response_string_royalty_fails() {
        let json = r#"{"royalty_units_credited":"not_a_number"}"#;
        let result = serde_json::from_str::<ConsumeCreditsResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_consume_credits_response_float_balance() -> Result<(), Box<dyn std::error::Error>> {
        // JSON floats that are exact integers should deserialise to u64
        let json = r#"{"balance_after_units":100.0}"#;
        // serde_json may or may not accept this depending on version; just verify it does not panic
        let _result = serde_json::from_str::<ConsumeCreditsResponse>(json);
        Ok(())
    }

    // ======================================================================
    // HMAC signature stability: same inputs always produce the exact same hex
    // ======================================================================

    #[test]
    fn test_hmac_signature_stability_across_invocations() -> Result<(), Box<dyn std::error::Error>>
    {
        let key = vec![0x55; 32];
        let ts = "1700000000";
        let method = "POST";
        let path = "/v1/credits/consume";
        let body =
            r#"{"customer_id":"cust-1","verification_id":"ver-1","origin":"https://example.com"}"#;
        let message = format!("{}:{}:{}:{}", ts, method, path, body);

        let mut signatures = Vec::new();
        for _ in 0..5 {
            let mut mac = HmacSha256::new_from_slice(&key)?;
            mac.update(message.as_bytes());
            signatures.push(hex::encode(mac.finalize().into_bytes()));
        }

        // All 5 signatures should be identical
        for sig in &signatures {
            assert_eq!(sig, &signatures[0]);
        }
        Ok(())
    }

    // ======================================================================
    // ConsumeCreditsBody: verify skip_serializing_if for Some("") vs None
    // ======================================================================

    #[test]
    fn test_consume_credits_body_some_empty_string_is_included(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Some("") is NOT None, so skip_serializing_if should NOT skip it
        let body = ConsumeCreditsBody {
            customer_id: "c".to_string(),
            verification_id: "v".to_string(),
            origin: "o".to_string(),
            issuer_kid: Some("".to_string()),
            environment: Some("".to_string()),
        };
        let json = serde_json::to_string(&body)?;
        assert!(
            json.contains("issuer_kid"),
            "Some(\"\") should still be serialised"
        );
        assert!(
            json.contains("environment"),
            "Some(\"\") should still be serialised"
        );
        Ok(())
    }
}
