// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! OpenAPI specification generator for the verifier API.
//!
//! Builds the OAS 3.1.0 document on demand from the runtime request and
//! response types using `schemars`. Internal and sandbox paths are stripped
//! before the spec is served to external callers.
//!
//! The `/v1/hosted/*` first-party browser endpoints invoked by provii-agegate
//! are deliberately omitted from the spec: they are not part of the
//! public-facing relying-party API surface and carry CSRF/session
//! semantics that do not round-trip through generated SDKs. Adding them
//! would leak internal implementation detail without any integrator
//! benefit.

// The `json!` macro from serde_json internally uses indexing operations that
// trigger `clippy::indexing_slicing`. This entire module is declarative JSON
// construction with no user-controlled indices, so the lint is not actionable.
#![allow(clippy::indexing_slicing)]

use schemars::{schema_for, JsonSchema};
use serde_json::{json, Value};
use worker::Response;

// Use the concrete request and response types.
use crate::routes::{
    challenge::{ChallengeDetailsResponse, ChallengeResponse, CreateChallengeRequest},
    redeem::{RedeemRequest, RedeemResponse},
    verify::{SubmitProofRequest, VerifyResponse},
};

// Representation of the challenge status payload.
#[derive(serde::Serialize, JsonSchema)]
struct ChallengeStatus {
    state: String,
    status: String,
    verified: bool,
    proof_verified: bool,
}

// Representation of a structured error response.
#[derive(serde::Serialize, JsonSchema)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    request_id: String,
}

/// Generate the complete OpenAPI specification at runtime from actual types.
pub fn generate_spec(version: &str, base_url: &str) -> Value {
    // Derive JSON schemas from the Rust types.
    let create_challenge_schema = schema_for!(CreateChallengeRequest);
    let challenge_response_schema = schema_for!(ChallengeResponse);
    let challenge_details_response_schema = schema_for!(ChallengeDetailsResponse);
    let submit_proof_schema = schema_for!(SubmitProofRequest);
    let verify_response_schema = schema_for!(VerifyResponse);
    let redeem_request_schema = schema_for!(RedeemRequest);
    let redeem_response_schema = schema_for!(RedeemResponse);
    let challenge_status_schema = schema_for!(ChallengeStatus);
    let error_response_schema = schema_for!(ErrorResponse);

    // Convert schemas into JSON values.
    // In schemars 1.0 the schema type implements Serialize directly.
    let create_challenge_json = serde_json::to_value(&create_challenge_schema).unwrap_or(json!({}));
    let challenge_response_json =
        serde_json::to_value(&challenge_response_schema).unwrap_or(json!({}));
    let submit_proof_json = serde_json::to_value(&submit_proof_schema).unwrap_or(json!({}));
    let verify_response_json = serde_json::to_value(&verify_response_schema).unwrap_or(json!({}));
    let redeem_request_json = serde_json::to_value(&redeem_request_schema).unwrap_or(json!({}));
    let redeem_response_json = serde_json::to_value(&redeem_response_schema).unwrap_or(json!({}));
    let challenge_status_json = serde_json::to_value(&challenge_status_schema).unwrap_or(json!({}));
    let error_response_json = serde_json::to_value(&error_response_schema).unwrap_or(json!({}));
    let challenge_details_response_json =
        serde_json::to_value(&challenge_details_response_schema).unwrap_or(json!({}));

    // Remove metadata fields and extract the schema definitions.
    let extract_schema = |mut schema_json: Value| -> Value {
        if let Some(obj) = schema_json.as_object_mut() {
            obj.remove("$schema");
            obj.remove("title");
            // The schema content is typically at the top level or within `definitions`.
            if let Some(_definitions) = obj.get("definitions") {
                // Preserve the full structure when nested definitions are present.
                json!(obj)
            } else {
                // Return the schema as-is when no nested definitions exist.
                json!(obj)
            }
        } else {
            schema_json
        }
    };

    let all_definitions = json!({
        "CreateChallengeRequest": extract_schema(create_challenge_json.clone()),
        "ChallengeResponse": extract_schema(challenge_response_json.clone()),
        "ChallengeDetailsResponse": extract_schema(challenge_details_response_json.clone()),
        "SubmitProofRequest": extract_schema(submit_proof_json.clone()),
        "VerifyResponse": extract_schema(verify_response_json.clone()),
        "RedeemRequest": extract_schema(redeem_request_json.clone()),
        "RedeemResponse": extract_schema(redeem_response_json.clone()),
        "ChallengeStatus": extract_schema(challenge_status_json.clone()),
        "ErrorResponse": extract_schema(error_response_json.clone()),
        "HealthCheckResponse": {
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["healthy", "degraded", "unhealthy"] },
                "timestamp": { "type": "integer", "description": "Unix timestamp in seconds" },
                "version": { "type": "string" },
                "checks": {
                    "type": "object",
                    "properties": {
                        "challenge_store": { "$ref": "#/components/schemas/SubsystemHealth" },
                        "nonce_store": { "$ref": "#/components/schemas/SubsystemHealth" },
                        "jwks_cache": { "$ref": "#/components/schemas/SubsystemHealth" },
                        "rate_limiter": { "$ref": "#/components/schemas/SubsystemHealth" },
                        "ban_store": { "$ref": "#/components/schemas/SubsystemHealth" }
                    }
                }
            }
        },
        "SubsystemHealth": {
            "type": "object",
            "properties": {
                "operational": { "type": "boolean" },
                "message": { "type": "string" },
                "metrics": { "type": "object" }
            },
            "required": ["operational"]
        },
        "CspReport": {
            "type": "object",
            "required": ["csp-report"],
            "properties": {
                "csp-report": {
                    "type": "object",
                    "properties": {
                        "document-uri": { "type": "string" },
                        "referrer": { "type": "string" },
                        "blocked-uri": { "type": "string" },
                        "violated-directive": { "type": "string" },
                        "effective-directive": { "type": "string" },
                        "original-policy": { "type": "string" },
                        "disposition": { "type": "string" },
                        "status-code": { "type": "integer" },
                        "script-sample": { "type": "string" },
                        "source-file": { "type": "string" },
                        "line-number": { "type": "integer" },
                        "column-number": { "type": "integer" }
                    }
                }
            }
        },
        "RegisterTestOriginRequest": {
            "type": "object",
            "required": ["origin", "api_key"],
            "properties": {
                "origin": { "type": "string", "description": "Origin URL to register for testing" },
                "min_age_years": { "type": "integer", "default": 18, "minimum": 0, "maximum": 150, "description": "Minimum age in years (default 18). Used for over_age proofs." },
                "api_key": { "type": "string", "description": "API key for the test origin" },
                "contact_email": { "type": "string", "description": "Optional contact email" },
                "proof_direction": { "type": "string", "enum": ["over_age", "under_age"], "default": "over_age", "description": "Proof direction. Defaults to over_age." },
                "max_age_years": { "type": "integer", "minimum": 0, "maximum": 150, "description": "Maximum age in years. Required when proof_direction is under_age." }
            }
        },
        "RegisterTestOriginResponse": {
            "type": "object",
            "properties": {
                "success": { "type": "boolean" },
                "message": { "type": "string" },
                "origin": { "type": "string" },
                "hmac_secret": { "type": "string", "description": "Returned only on first registration" },
                "client_id": { "type": "string", "description": "Returned only on first registration" },
                "security_note": { "type": "string" },
                "expires_at": { "type": "integer", "description": "Unix timestamp when the registration expires" },
                "ttl_seconds": { "type": "integer", "description": "Time-to-live in seconds" },
                "already_existed": { "type": "boolean", "description": "True if the origin was already registered (idempotent hit)" },
                "test_instructions": {
                    "type": "object",
                    "properties": {
                        "endpoint": { "type": "string" },
                        "example_curl": { "type": "string" },
                        "example_javascript": { "type": "string" },
                        "agegate_js_snippet": { "type": "string" }
                    }
                }
            }
        },
        "SimulateProofRequest": {
            "type": "object",
            "required": ["challenge_id", "submit_secret", "outcome"],
            "properties": {
                "challenge_id": { "type": "string", "format": "uuid", "description": "Challenge UUID to simulate proof for" },
                "submit_secret": { "type": "string", "description": "Base64url-encoded 32-byte submit secret (43 characters)" },
                "outcome": { "type": "string", "enum": ["verified", "age_not_met"], "description": "Desired simulation outcome" }
            }
        },
        "SimulateProofResponse": {
            "type": "object",
            "required": ["result", "state"],
            "properties": {
                "result": { "type": "string", "description": "Always ok on success" },
                "state": { "type": "string", "description": "Resulting challenge state after simulation" }
            }
        }
    });

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Provii Verifier API",
            "version": version,
            "description": "Zero-knowledge proof based age verification service. This API enables privacy-preserving age verification without revealing personal information.",
            "contact": {
                "name": "Provii Support",
                "email": "support@provii.app",
                "url": "https://provii.app"
            }
        },
        "servers": [
            {
                // SECURITY: Strip /v1 suffix to prevent double-prefix /v1/v1/ in code generators (XA3-1).
                // Paths in this spec already include the /v1/ prefix.
                "url": base_url.trim_end_matches("/v1"),
                "description": "Production server"
            }
        ],
        "tags": [
            {
                "name": "Challenge",
                "description": "Challenge creation, polling, and redemption for age verification"
            },
            {
                "name": "Verification",
                "description": "Zero-knowledge proof submission and verification"
            },
            {
                "name": "Operations",
                "description": "Health checks, metrics, and monitoring"
            },
            {
                "name": "Meta",
                "description": "API documentation endpoints"
            },
            {
                "name": "Sandbox",
                "description": "Sandbox-only endpoints for testing"
            },
            {
                "name": "System",
                "description": "System health and monitoring"
            }
        ],
        "paths": {
            "/v1/challenge": {
                "post": {
                    "summary": "Create age verification challenge",
                    "description": "Creates a new challenge for age verification using PKCE flow. The origin must be pre-approved.",
                    "operationId": "createVerificationChallenge",
                    "tags": ["Challenge"],
                    "security": [{ "ApiKeyAuth": [] }],
                    "parameters": [
                        {
                            "name": "Origin",
                            "in": "header",
                            "required": true,
                            "schema": { "type": "string" },
                            "description": "Origin of the request. Must be in the approved origins list.",
                            "example": "https://example.com"
                        },
                        {
                            "name": "X-API-Key",
                            "in": "header",
                            "required": true,
                            "schema": { "type": "string" },
                            "description": "API key issued to the relying party.",
                            "example": "pk_live_XXXXXXXXXXXXXXXX"
                        }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": create_challenge_json
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Challenge created successfully",
                            "content": {
                                "application/json": {
                                    "schema": challenge_response_json
                                }
                            }
                        },
                        "400": {
                            "description": "Bad request",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "403": {
                            "description": "Access denied",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "429": {
                            "description": "Rate limit exceeded",
                            "headers": {
                                "Retry-After": {
                                    "schema": { "type": "integer" },
                                    "description": "Seconds until the rate limit resets"
                                }
                            },
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/challenge/{session_id}": {
                "get": {
                    "summary": "Poll challenge status",
                    "description": "Check the current status of a challenge",
                    "operationId": "pollChallengeStatus",
                    "tags": ["Challenge"],
                    "security": [],
                    "parameters": [
                        {
                            "name": "session_id",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string", "format": "uuid" },
                            "description": "Challenge session ID"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Challenge status",
                            "content": {
                                "application/json": {
                                    "schema": challenge_status_json
                                }
                            }
                        },
                        "404": {
                            "description": "Not found",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "410": {
                            "description": "Gone",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/challenge/{session_id}/redeem": {
                "post": {
                    "summary": "Redeem verified challenge",
                    "description": "Complete verification by providing PKCE code_verifier",
                    "operationId": "redeemVerificationChallenge",
                    "tags": ["Challenge"],
                    "security": [],
                    "parameters": [
                        {
                            "name": "session_id",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string", "format": "uuid" },
                            "description": "Challenge session ID"
                        }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": redeem_request_json
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Challenge redeemed",
                            "content": {
                                "application/json": {
                                    "schema": redeem_response_json
                                }
                            }
                        },
                        "400": {
                            "description": "Bad request",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "404": {
                            "description": "Not found",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "409": {
                            "description": "Conflict",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "410": {
                            "description": "Gone",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/verify": {
                "post": {
                    "summary": "Submit age proof",
                    "description": "Submit zero-knowledge proof for verification",
                    "operationId": "submitVerification",
                    "tags": ["Verification"],
                    "security": [],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": submit_proof_json
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Proof verified",
                            "content": {
                                "application/json": {
                                    "schema": verify_response_json
                                }
                            }
                        },
                        "400": {
                            "description": "Bad request",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "403": {
                            "description": "Access denied",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "404": {
                            "description": "Not found",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "410": {
                            "description": "Gone",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/health": {
                "get": {
                    "summary": "Health check",
                    "operationId": "health",
                    "tags": ["System"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "Service is healthy",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": { "type": "string", "example": "healthy", "enum": ["healthy", "degraded", "unhealthy"] },
                                            "timestamp": { "type": "integer", "format": "int64" },
                                            "version": { "type": "string", "example": "v1" }
                                        },
                                        "required": ["status", "timestamp", "version"]
                                    }
                                }
                            }
                        },
                        "503": {
                            "description": "Service unhealthy",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": { "type": "string", "example": "unhealthy", "enum": ["healthy", "degraded", "unhealthy"] },
                                            "timestamp": { "type": "integer", "format": "int64" },
                                            "version": { "type": "string", "example": "v1" }
                                        },
                                        "required": ["status", "timestamp", "version"]
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/health/detailed": {
                "get": {
                    "summary": "Detailed health check",
                    "description": "Returns detailed health status including subsystem checks for challenge store, nonce store, JWKS cache, rate limiter, and ban store",
                    "operationId": "healthDetailed",
                    "tags": ["Operations"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "Detailed health status",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/HealthCheckResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "503": {
                            "description": "Service unhealthy",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/HealthCheckResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/metrics": {
                "get": {
                    "summary": "Prometheus metrics",
                    "description": "Returns metrics in Prometheus text exposition format",
                    "operationId": "metrics",
                    "tags": ["Operations"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "Metrics in Prometheus format",
                            "content": {
                                "text/plain": {
                                    "schema": { "type": "string" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/csp-report": {
                "post": {
                    "summary": "Receive CSP violation report",
                    "description": "Endpoint for browsers to submit Content Security Policy violation reports. Returns 204 with no body.",
                    "operationId": "cspReport",
                    "tags": ["Meta"],
                    "security": [],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/csp-report": {
                                "schema": { "$ref": "#/components/schemas/CspReport" }
                            }
                        }
                    },
                    "responses": {
                        "204": {
                            "description": "Report received"
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/openapi.json": {
                "get": {
                    "summary": "OpenAPI specification",
                    "description": "Returns this OpenAPI specification document",
                    "operationId": "openapiSpec",
                    "tags": ["Meta"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "OpenAPI 3.1.0 specification",
                            "content": {
                                "application/json": {
                                    "schema": { "type": "object" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/docs": {
                "get": {
                    "summary": "API documentation",
                    "description": "Interactive API documentation rendered from the OpenAPI specification",
                    "operationId": "apiDocs",
                    "tags": ["Meta"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "HTML documentation page",
                            "content": {
                                "text/html": {
                                    "schema": { "type": "string" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/challenge/{session_id}/details": {
                "get": {
                    "summary": "Get challenge details",
                    "description": "Returns full challenge details including short code, deep link data, and expiry. Used by the wallet app to display challenge information.",
                    "operationId": "challengeDetails",
                    "tags": ["Challenge"],
                    "security": [],
                    "parameters": [
                        {
                            "name": "session_id",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string", "format": "uuid" },
                            "description": "Challenge session ID"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Challenge details",
                            "content": {
                                "application/json": {
                                    "schema": challenge_details_response_json.clone()
                                }
                            }
                        },
                        "404": {
                            "description": "Challenge not found",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "410": {
                            "description": "Challenge expired",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/challenge/by-code/{code}": {
                "get": {
                    "summary": "Look up challenge by short code",
                    "description": "Retrieves challenge details using the 12-digit numeric short code (formatted as XXXX XXXX XXXX). Used for manual code entry as an alternative to QR scanning.",
                    "operationId": "challengeByCode",
                    "tags": ["Challenge"],
                    "security": [],
                    "parameters": [
                        {
                            "name": "code",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string" },
                            "description": "12-digit numeric short code"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Challenge details",
                            "content": {
                                "application/json": {
                                    "schema": challenge_details_response_json
                                }
                            }
                        },
                        "404": {
                            "description": "No challenge found for this code",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "410": {
                            "description": "Challenge expired",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/register-test-origin": {
                "post": {
                    "summary": "Register test origin (sandbox only)",
                    "description": "Registers a new origin for testing in the sandbox environment. Not available in production.",
                    "operationId": "registerTestOrigin",
                    "tags": ["Sandbox"],
                    "security": [{ "ApiKeyAuth": [] }],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/RegisterTestOriginRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Origin registered successfully",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/RegisterTestOriginResponse" }
                                }
                            }
                        },
                        "400": {
                            "description": "Bad request",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "403": {
                            "description": "Not available in production",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "429": {
                            "description": "Rate limit exceeded",
                            "headers": {
                                "Retry-After": {
                                    "schema": { "type": "integer" },
                                    "description": "Seconds until the rate limit resets"
                                }
                            },
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/hosted/sandbox/simulate-proof": {
                "post": {
                    "summary": "Simulate proof verification (sandbox only)",
                    "description": "Simulates a wallet proof submission for testing. Only available in sandbox environment.",
                    "operationId": "simulateProof",
                    "tags": ["Sandbox"],
                    "security": [],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/SimulateProofRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Proof simulation succeeded",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/SimulateProofResponse" }
                                }
                            }
                        },
                        "400": {
                            "description": "Bad request (invalid fields)",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "403": {
                            "description": "Invalid submit_secret",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "404": {
                            "description": "Not found (production) or challenge not found",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "410": {
                            "description": "Challenge expired or already consumed",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": all_definitions,
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "API key issued to relying parties. Verified via Argon2id (provii-verifier/src/security/auth.rs:412). Expert verifiers additionally embed an `Authorizer` envelope (key_id + timestamp + nonce + HMAC-SHA256 over the canonical request body) inside the request payload, not as a separate header. See provii-verifier/src/security/auth.rs:664 (verify_hmac) and provii-verifier/src/types/auth.rs."
                }
            }
        }
    })
}

/// Recursively remove `$schema` keys injected by schemars. OpenAPI 3.1 ties
/// schema dialects to the document's `jsonSchemaDialect`, so repeating
/// `$schema` inside every schema object is noise at best and inconsistent at
/// worst.
fn strip_schema_keyword(val: &mut Value) {
    match val {
        Value::Object(map) => {
            map.remove("$schema");
            for v in map.values_mut() {
                strip_schema_keyword(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                strip_schema_keyword(v);
            }
        }
        _ => {}
    }
}

/// Tags whose paths should be stripped from the public spec.
const PRIVATE_TAGS: &[&str] = &["Internal", "Sandbox"];

/// Remove paths tagged as internal or sandbox from the spec.
/// Prevents information leakage about service-to-service APIs.
fn strip_private_paths(mut spec: Value) -> Value {
    if let Some(paths) = spec.get_mut("paths").and_then(|p| p.as_object_mut()) {
        paths.retain(|_path, methods| {
            if let Some(obj) = methods.as_object() {
                // Keep the path if none of its methods have a private tag
                !obj.values().any(|method| {
                    method
                        .get("tags")
                        .and_then(|t| t.as_array())
                        .map(|tags| {
                            tags.iter().any(|t| {
                                t.as_str()
                                    .map(|s| PRIVATE_TAGS.contains(&s))
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false)
                })
            } else {
                true
            }
        });
    }
    spec
}

/// Per-isolate cache for the serialised OpenAPI JSON. The spec is deterministic
/// for a given (version, base_url) pair and these values are constant within an
/// isolate, so generating once and reusing saves ~15ms CPU per request (H-28).
static OPENAPI_JSON_CACHE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Serve the OpenAPI specification.
pub fn serve_openapi_json(version: &str, base_url: &str) -> worker::Result<Response> {
    let json_body = OPENAPI_JSON_CACHE.get_or_init(|| {
        let mut spec = strip_private_paths(generate_spec(version, base_url));
        strip_schema_keyword(&mut spec);
        // serde_json::to_string cannot fail on a valid Value
        serde_json::to_string(&spec).unwrap_or_default()
    });

    let mut response = Response::from_bytes(json_body.as_bytes().to_vec())?;

    // Prepare response headers.
    let headers = response.headers_mut();
    // SECURITY: ASVS V4.1.1 - Add explicit charset to Content-Type
    headers.set("Content-Type", "application/json; charset=utf-8")?;
    // SECURITY: ASVS V14.2.5 - API specification must not be publicly cached
    headers.set(
        "Cache-Control",
        "private, no-store, must-revalidate, max-age=0",
    )?;
    headers.set("Pragma", "no-cache")?;
    headers.set("Expires", "0")?;
    // SECURITY: No wildcard CORS on API spec (O-1). Spec is accessible via direct
    // navigation or same-origin fetch. Cross-origin access is not required.
    headers.set("X-Content-Type-Options", "nosniff")?;

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Structure Tests - ChallengeStatus
    // ========================================================================

    #[test]
    fn test_challenge_status_structure() {
        let status = ChallengeStatus {
            state: "pending".to_string(),
            status: "waiting".to_string(),
            verified: false,
            proof_verified: false,
        };
        assert_eq!(status.state, "pending");
        assert_eq!(status.status, "waiting");
        assert!(!status.verified);
        assert!(!status.proof_verified);
    }

    #[test]
    fn test_challenge_status_verified() {
        let status = ChallengeStatus {
            state: "verified".to_string(),
            status: "complete".to_string(),
            verified: true,
            proof_verified: true,
        };
        assert!(status.verified);
        assert!(status.proof_verified);
    }

    #[test]
    fn test_challenge_status_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let status = ChallengeStatus {
            state: "verified".to_string(),
            status: "complete".to_string(),
            verified: true,
            proof_verified: true,
        };
        let json = serde_json::to_value(&status)?;
        assert!(json.get("state").is_some());
        assert!(json.get("status").is_some());
        assert!(json.get("verified").is_some());
        assert!(json.get("proof_verified").is_some());
        Ok(())
    }

    #[test]
    fn test_challenge_status_json_values() -> Result<(), Box<dyn std::error::Error>> {
        let status = ChallengeStatus {
            state: "pending".to_string(),
            status: "waiting".to_string(),
            verified: false,
            proof_verified: false,
        };
        let json = serde_json::to_value(&status)?;
        assert_eq!(json["state"], "pending");
        assert_eq!(json["status"], "waiting");
        assert_eq!(json["verified"], false);
        assert_eq!(json["proof_verified"], false);
        Ok(())
    }

    // ========================================================================
    // Structure Tests - ErrorResponse
    // ========================================================================

    #[test]
    fn test_error_response_structure() {
        let err = ErrorResponse {
            error: "Invalid request".to_string(),
            code: Some("BAD_REQUEST".to_string()),
            request_id: "test-req-id".to_string(),
        };
        assert_eq!(err.error, "Invalid request");
        assert_eq!(err.code, Some("BAD_REQUEST".to_string()));
        assert_eq!(err.request_id, "test-req-id");
    }

    #[test]
    fn test_error_response_without_code() {
        let err = ErrorResponse {
            error: "Internal error".to_string(),
            code: None,
            request_id: "test-req-id".to_string(),
        };
        assert_eq!(err.error, "Internal error");
        assert!(err.code.is_none());
        assert_eq!(err.request_id, "test-req-id");
    }

    #[test]
    fn test_error_response_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let err = ErrorResponse {
            error: "Test error".to_string(),
            code: Some("TEST".to_string()),
            request_id: "test-req-id".to_string(),
        };
        let json = serde_json::to_value(&err)?;
        assert!(json.get("error").is_some());
        assert!(json.get("code").is_some());
        assert!(json.get("request_id").is_some());
        Ok(())
    }

    #[test]
    fn test_error_response_serialization_no_code() -> Result<(), Box<dyn std::error::Error>> {
        let err = ErrorResponse {
            error: "Test error".to_string(),
            code: None,
            request_id: "test-req-id".to_string(),
        };
        let json = serde_json::to_value(&err)?;
        assert!(json.get("error").is_some());
        // code is skipped when None due to skip_serializing_if
        assert!(json.get("code").is_none());
        assert!(json.get("request_id").is_some());
        Ok(())
    }

    // ========================================================================
    // OpenAPI Spec Generation Tests
    // ========================================================================

    #[test]
    fn test_generate_spec_openapi_version() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert_eq!(spec["openapi"], "3.1.0");
    }

    #[test]
    fn test_generate_spec_info_title() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert_eq!(spec["info"]["title"], "Provii Verifier API");
    }

    #[test]
    fn test_generate_spec_info_version() {
        let spec = generate_spec("2.1.0", "https://api.example.com");
        assert_eq!(spec["info"]["version"], "2.1.0");
    }

    #[test]
    fn test_generate_spec_info_description() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let desc = spec["info"]["description"]
            .as_str()
            .ok_or("description not a string")?;
        assert!(desc.contains("Zero-knowledge proof"));
        assert!(desc.contains("age verification"));
        Ok(())
    }

    #[test]
    fn test_generate_spec_info_contact() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert_eq!(spec["info"]["contact"]["name"], "Provii Support");
        assert_eq!(spec["info"]["contact"]["email"], "support@provii.app");
        assert_eq!(spec["info"]["contact"]["url"], "https://provii.app");
    }

    #[test]
    fn test_generate_spec_servers() {
        let base_url = "https://verifier.example.com";
        let spec = generate_spec("1.0.0", base_url);
        assert!(spec["servers"].is_array());
        assert_eq!(spec["servers"][0]["url"], base_url);
        assert_eq!(spec["servers"][0]["description"], "Production server");
    }

    #[test]
    fn test_generate_spec_servers_custom_url() {
        let base_url = "https://custom.api.test";
        let spec = generate_spec("1.0.0", base_url);
        assert_eq!(spec["servers"][0]["url"], base_url);
    }

    #[test]
    fn test_generate_spec_has_tags() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["tags"].is_array());
        let tags = spec["tags"].as_array().ok_or("tags not an array")?;
        assert!(tags.len() >= 4);
        Ok(())
    }

    #[test]
    fn test_generate_spec_challenge_tag() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["tags"].as_array().ok_or("tags not an array")?;
        let challenge_tag = tags
            .iter()
            .find(|t| t["name"] == "Challenge")
            .ok_or("Challenge tag not found")?;
        let desc = challenge_tag["description"]
            .as_str()
            .ok_or("description not a string")?;
        assert!(desc.contains("Challenge"));
        Ok(())
    }

    #[test]
    fn test_generate_spec_verification_tag() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["tags"].as_array().ok_or("tags not an array")?;
        let _verification_tag = tags
            .iter()
            .find(|t| t["name"] == "Verification")
            .ok_or("Verification tag not found")?;
        Ok(())
    }

    #[test]
    fn test_generate_spec_system_tag() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["tags"].as_array().ok_or("tags not an array")?;
        let _system_tag = tags
            .iter()
            .find(|t| t["name"] == "System")
            .ok_or("System tag not found")?;
        Ok(())
    }

    // ========================================================================
    // Path Tests
    // ========================================================================

    #[test]
    fn test_generate_spec_has_paths() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"].is_object());
    }

    #[test]
    fn test_generate_spec_challenge_path() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"]["/v1/challenge"].is_object());
        assert!(spec["paths"]["/v1/challenge"]["post"].is_object());
    }

    #[test]
    fn test_generate_spec_challenge_path_summary() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let summary = spec["paths"]["/v1/challenge"]["post"]["summary"]
            .as_str()
            .ok_or("summary not a string")?;
        assert!(summary.contains("challenge"));
        Ok(())
    }

    #[test]
    fn test_generate_spec_challenge_path_operation_id() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert_eq!(
            spec["paths"]["/v1/challenge"]["post"]["operationId"],
            "createVerificationChallenge"
        );
    }

    #[test]
    fn test_generate_spec_challenge_path_tags() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["paths"]["/v1/challenge"]["post"]["tags"]
            .as_array()
            .ok_or("tags not an array")?;
        assert!(tags.contains(&json!("Challenge")));
        Ok(())
    }

    #[test]
    fn test_generate_spec_challenge_path_required_headers() -> Result<(), Box<dyn std::error::Error>>
    {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let params = spec["paths"]["/v1/challenge"]["post"]["parameters"]
            .as_array()
            .ok_or("parameters not an array")?;

        let origin = params
            .iter()
            .find(|p| p["name"] == "Origin")
            .ok_or("Origin param not found")?;
        assert_eq!(origin["required"], true);

        let api_key = params
            .iter()
            .find(|p| p["name"] == "X-API-Key")
            .ok_or("X-API-Key param not found")?;
        assert_eq!(api_key["required"], true);
        Ok(())
    }

    #[test]
    fn test_generate_spec_challenge_path_request_body() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"]["/v1/challenge"]["post"]["requestBody"].is_object());
        assert_eq!(
            spec["paths"]["/v1/challenge"]["post"]["requestBody"]["required"],
            true
        );
    }

    #[test]
    fn test_generate_spec_challenge_path_responses() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let responses = &spec["paths"]["/v1/challenge"]["post"]["responses"];
        assert!(responses["201"].is_object());
        assert!(responses["400"].is_object());
        assert!(responses["403"].is_object());
        assert!(responses["500"].is_object());
    }

    #[test]
    fn test_generate_spec_poll_challenge_path() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"]["/v1/challenge/{session_id}"].is_object());
        assert!(spec["paths"]["/v1/challenge/{session_id}"]["get"].is_object());
    }

    #[test]
    fn test_generate_spec_poll_challenge_operation_id() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert_eq!(
            spec["paths"]["/v1/challenge/{session_id}"]["get"]["operationId"],
            "pollChallengeStatus"
        );
    }

    #[test]
    fn test_generate_spec_poll_challenge_sid_param() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let params = spec["paths"]["/v1/challenge/{session_id}"]["get"]["parameters"]
            .as_array()
            .ok_or("parameters not an array")?;
        let sid = params
            .iter()
            .find(|p| p["name"] == "session_id")
            .ok_or("session_id param not found")?;
        assert_eq!(sid["required"], true);
        assert_eq!(sid["schema"]["format"], "uuid");
        Ok(())
    }

    #[test]
    fn test_generate_spec_redeem_path() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"]["/v1/challenge/{session_id}/redeem"].is_object());
        assert!(spec["paths"]["/v1/challenge/{session_id}/redeem"]["post"].is_object());
    }

    #[test]
    fn test_generate_spec_redeem_operation_id() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert_eq!(
            spec["paths"]["/v1/challenge/{session_id}/redeem"]["post"]["operationId"],
            "redeemVerificationChallenge"
        );
    }

    #[test]
    fn test_generate_spec_redeem_responses() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let responses = &spec["paths"]["/v1/challenge/{session_id}/redeem"]["post"]["responses"];
        assert!(responses["200"].is_object());
        assert!(responses["400"].is_object());
        assert!(responses["404"].is_object());
        assert!(responses["409"].is_object());
        assert!(responses["410"].is_object());
    }

    #[test]
    fn test_generate_spec_verify_path() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"]["/v1/verify"].is_object());
        assert!(spec["paths"]["/v1/verify"]["post"].is_object());
    }

    #[test]
    fn test_generate_spec_verify_operation_id() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert_eq!(
            spec["paths"]["/v1/verify"]["post"]["operationId"],
            "submitVerification"
        );
    }

    #[test]
    fn test_generate_spec_verify_responses() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let responses = &spec["paths"]["/v1/verify"]["post"]["responses"];
        assert!(responses["200"].is_object());
        assert!(responses["400"].is_object());
        assert!(responses["403"].is_object());
        assert!(responses["404"].is_object());
        assert!(responses["410"].is_object());
    }

    #[test]
    fn test_generate_spec_health_path() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"]["/health"].is_object());
        assert!(spec["paths"]["/health"]["get"].is_object());
    }

    #[test]
    fn test_generate_spec_health_operation_id() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert_eq!(spec["paths"]["/health"]["get"]["operationId"], "health");
    }

    #[test]
    fn test_generate_spec_health_response() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"]["/health"]["get"]["responses"]["200"].is_object());
    }

    // ========================================================================
    // New Endpoint Tests
    // ========================================================================

    #[test]
    fn test_generate_spec_health_detailed_path() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/health/detailed"]["get"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "healthDetailed");
        let tags = path["tags"].as_array().ok_or("tags not an array")?;
        assert!(tags.contains(&json!("Operations")));
        Ok(())
    }

    #[test]
    fn test_generate_spec_metrics_path() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/metrics"]["get"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "metrics");
    }

    #[test]
    fn test_generate_spec_csp_report_path() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/csp-report"]["post"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "cspReport");
        assert!(path["responses"]["204"].is_object());
    }

    #[test]
    fn test_generate_spec_openapi_json_path() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/openapi.json"]["get"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "openapiSpec");
    }

    #[test]
    fn test_generate_spec_docs_path() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/docs"]["get"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "apiDocs");
    }

    // Internal /v1/internal/* endpoints were removed when provii-verifier was
    // merged into provii-verifier (see worker_routes.rs notes). The spec no
    // longer advertises them.

    #[test]
    fn test_generate_spec_challenge_details_path() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/challenge/{session_id}/details"]["get"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "challengeDetails");
    }

    #[test]
    fn test_generate_spec_challenge_by_code_path() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/challenge/by-code/{code}"]["get"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "challengeByCode");
    }

    #[test]
    fn test_generate_spec_register_test_origin_path() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/register-test-origin"]["post"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "registerTestOrigin");
        let tags = path["tags"].as_array().ok_or("tags not an array")?;
        assert!(tags.contains(&json!("Sandbox")));
        Ok(())
    }

    #[test]
    fn test_generate_spec_has_security_schemes() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["components"]["securitySchemes"].is_object());
        assert!(spec["components"]["securitySchemes"]["ApiKeyAuth"].is_object());
    }

    // ========================================================================
    // Components/Schemas Tests
    // ========================================================================

    #[test]
    fn test_generate_spec_has_components() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["components"].is_object());
        assert!(spec["components"]["schemas"].is_object());
    }

    #[test]
    fn test_generate_spec_has_create_challenge_request_schema() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["components"]["schemas"]["CreateChallengeRequest"].is_object());
    }

    #[test]
    fn test_generate_spec_has_challenge_response_schema() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["components"]["schemas"]["ChallengeResponse"].is_object());
    }

    #[test]
    fn test_generate_spec_has_submit_proof_request_schema() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["components"]["schemas"]["SubmitProofRequest"].is_object());
    }

    #[test]
    fn test_generate_spec_has_verify_response_schema() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["components"]["schemas"]["VerifyResponse"].is_object());
    }

    #[test]
    fn test_generate_spec_has_redeem_request_schema() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["components"]["schemas"]["RedeemRequest"].is_object());
    }

    #[test]
    fn test_generate_spec_has_redeem_response_schema() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["components"]["schemas"]["RedeemResponse"].is_object());
    }

    #[test]
    fn test_generate_spec_has_challenge_status_schema() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["components"]["schemas"]["ChallengeStatus"].is_object());
    }

    #[test]
    fn test_generate_spec_has_error_response_schema() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["components"]["schemas"]["ErrorResponse"].is_object());
    }

    // ========================================================================
    // Version and URL Variation Tests
    // ========================================================================

    #[test]
    fn test_generate_spec_different_versions() {
        let spec1 = generate_spec("1.0.0", "https://api.example.com");
        let spec2 = generate_spec("2.5.3", "https://api.example.com");
        assert_eq!(spec1["info"]["version"], "1.0.0");
        assert_eq!(spec2["info"]["version"], "2.5.3");
    }

    #[test]
    fn test_generate_spec_different_base_urls() {
        let spec1 = generate_spec("1.0.0", "https://api1.example.com");
        let spec2 = generate_spec("1.0.0", "https://api2.example.com");
        assert_eq!(spec1["servers"][0]["url"], "https://api1.example.com");
        assert_eq!(spec2["servers"][0]["url"], "https://api2.example.com");
    }

    #[test]
    fn test_generate_spec_localhost_url() {
        let spec = generate_spec("1.0.0", "http://localhost:8787");
        assert_eq!(spec["servers"][0]["url"], "http://localhost:8787");
    }

    #[test]
    fn test_generate_spec_empty_version() {
        let spec = generate_spec("", "https://api.example.com");
        assert_eq!(spec["info"]["version"], "");
    }

    #[test]
    fn test_generate_spec_semantic_version() {
        let spec = generate_spec("1.2.3-beta.1", "https://api.example.com");
        assert_eq!(spec["info"]["version"], "1.2.3-beta.1");
    }

    // ========================================================================
    // JSON Structure Validation Tests
    // ========================================================================

    #[test]
    fn test_generate_spec_is_valid_json() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let json_str = serde_json::to_string(&spec)?;
        assert!(serde_json::from_str::<serde_json::Value>(&json_str).is_ok());
        Ok(())
    }

    #[test]
    fn test_generate_spec_components_schemas_is_object() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["components"]["schemas"].is_object());
        let schemas = spec["components"]["schemas"]
            .as_object()
            .ok_or("schemas not an object")?;
        // Derived + hand-written schemas. Loose lower bound so new additions
        // do not break the test.
        assert!(schemas.len() >= 16);
        Ok(())
    }

    #[test]
    fn test_generate_spec_paths_count() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let paths = spec["paths"].as_object().ok_or("paths not an object")?;
        // 15 public paths + 2 sandbox paths (stripped by strip_private_paths
        // before serving). Keep the assertion loose so future additions do
        // not break the test.
        assert!(paths.len() >= 14);
        Ok(())
    }

    #[test]
    fn test_generate_spec_tags_count() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["tags"].as_array().ok_or("tags not an array")?;
        // Challenge, Verification, Operations, Meta, Sandbox, System.
        assert_eq!(tags.len(), 6);
        Ok(())
    }

    // ========================================================================
    // Snapshot Regeneration
    // ========================================================================

    /// Regenerates `openapi/openapi.json` from the runtime generator. The
    /// `publish-openapi.yml` workflow `cp`s this file into the signed R2
    /// artefact, so it must stay byte-identical to what `generate_spec`
    /// emits with production env values (`API_VERSION` + `API_BASE_URL`
    /// from `wrangler.toml`). To regenerate:
    ///
    ///     UPDATE_OPENAPI_SNAPSHOT=1 cargo test --lib \
    ///       --target wasm32-unknown-unknown \
    ///       routes::openapi::tests::regen_openapi_snapshot
    ///
    /// Runs via `wasm-bindgen-test-runner` (Node executor) because the
    /// crate's lib does not compile on native targets (worker-binding
    /// references in unrelated modules). The test imports Node's `fs`,
    /// `process.cwd`, and `process.env` via `wasm_bindgen` extern blocks
    /// and writes the formatted spec to `<cwd>/openapi/openapi.json`.
    /// No-op without the env flag so default `cargo test` runs do not
    /// mutate the working tree.
    ///
    /// Note: must be invoked from the crate root so `process.cwd()`
    /// resolves to `<repo>/provii-verifier/`. Cargo does this automatically.
    #[cfg(target_arch = "wasm32")]
    mod regen_node_bindings {
        use wasm_bindgen::prelude::*;

        // Direct Node-module imports via wasm-bindgen. wasm-bindgen's test
        // runner emits a CommonJS shim that resolves these as `require(...)`.
        #[wasm_bindgen(module = "fs")]
        extern "C" {
            #[wasm_bindgen(js_name = writeFileSync)]
            pub fn write_file_sync(path: &str, data: &js_sys::Uint8Array);
        }

        #[wasm_bindgen]
        extern "C" {
            #[wasm_bindgen(js_namespace = process, js_name = cwd)]
            pub fn cwd() -> String;
        }

        #[wasm_bindgen(inline_js = "export function read_env(name) { return process.env[name]; }")]
        extern "C" {
            pub fn read_env(name: &str) -> Option<String>;
        }
    }

    /// Reads `process.env.UPDATE_OPENAPI_SNAPSHOT` via the Node runtime.
    #[cfg(target_arch = "wasm32")]
    fn update_snapshot_flag() -> Option<String> {
        regen_node_bindings::read_env("UPDATE_OPENAPI_SNAPSHOT")
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    #[allow(
        clippy::expect_used,
        reason = "regen helper: serialising a Value produced by generate_spec \
                  cannot fail under any input. A panic here is a clearer \
                  failure mode than silently writing nothing."
    )]
    fn regen_openapi_snapshot() {
        if update_snapshot_flag().as_deref() != Some("1") {
            return;
        }

        // Production values from `wrangler.toml` (top-level [vars]).
        let version = "1.0.0";
        let base_url = "https://verify.provii.app/v1";
        let spec = generate_spec(version, base_url);

        // Match the existing on-disk format: 4-space indent, trailing newline.
        let mut buf = Vec::with_capacity(64 * 1024);
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
        serde::Serialize::serialize(&spec, &mut ser).expect("serialize spec to JSON");
        buf.push(b'\n');

        let path = format!("{}/openapi/openapi.json", regen_node_bindings::cwd());
        let body = js_sys::Uint8Array::from(buf.as_slice());
        regen_node_bindings::write_file_sync(&path, &body);
    }

    // ========================================================================
    // Property-Based Tests
    // ========================================================================

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: OpenAPI version is always 3.1.0
        #[test]
        fn prop_openapi_version_constant(
            version in "[0-9]+\\.[0-9]+\\.[0-9]+",
            base_url in "https?://[a-z]{3,10}\\.[a-z]{2,10}\\.[a-z]{2,3}"
        ) {
            let spec = generate_spec(&version, &base_url);
            prop_assert_eq!(spec["openapi"].as_str(), Some("3.1.0"));
        }

        /// Property: Version parameter is preserved in spec
        #[test]
        fn prop_version_preserved(
            version in "[0-9]+\\.[0-9]+\\.[0-9]+",
            base_url in "https://[a-z]{3,10}\\.com"
        ) {
            let spec = generate_spec(&version, &base_url);
            prop_assert_eq!(spec["info"]["version"].as_str(), Some(version.as_str()));
        }

        /// Property: Base URL is preserved in servers
        #[test]
        fn prop_base_url_preserved(
            version in "1\\.0\\.0",
            base_url in "https://[a-z]{3,10}\\.com"
        ) {
            let spec = generate_spec(&version, &base_url);
            prop_assert_eq!(spec["servers"][0]["url"].as_str(), Some(base_url.as_str()));
        }

        /// Property: Spec always has required top-level fields
        #[test]
        fn prop_has_required_fields(
            version in "[0-9]+\\.[0-9]+\\.[0-9]+",
            base_url in "https://[a-z]{3,10}\\.com"
        ) {
            let spec = generate_spec(&version, &base_url);
            prop_assert!(spec.get("openapi").is_some());
            prop_assert!(spec.get("info").is_some());
            prop_assert!(spec.get("servers").is_some());
            prop_assert!(spec.get("tags").is_some());
            prop_assert!(spec.get("paths").is_some());
            prop_assert!(spec.get("components").is_some());
        }

        /// Property: Info object always has required fields
        #[test]
        fn prop_info_has_required_fields(
            version in "[0-9]+\\.[0-9]+\\.[0-9]+",
            base_url in "https://[a-z]{3,10}\\.com"
        ) {
            let spec = generate_spec(&version, &base_url);
            prop_assert!(spec["info"].get("title").is_some());
            prop_assert!(spec["info"].get("version").is_some());
            prop_assert!(spec["info"].get("description").is_some());
            prop_assert!(spec["info"].get("contact").is_some());
        }

        /// Property: All paths are objects
        #[test]
        fn prop_all_paths_are_objects(
            version in "1\\.0\\.0",
            base_url in "https://[a-z]{3,10}\\.com"
        ) {
            let spec = generate_spec(&version, &base_url);
            let paths = spec["paths"].as_object()
                .ok_or_else(|| TestCaseError::fail("paths not an object"))?;
            for (_path, methods) in paths {
                prop_assert!(methods.is_object());
            }
        }

        /// Property: All schemas exist in components
        #[test]
        fn prop_all_schemas_exist(
            version in "1\\.0\\.0",
            base_url in "https://[a-z]{3,10}\\.com"
        ) {
            let spec = generate_spec(&version, &base_url);
            let schemas = spec["components"]["schemas"].as_object()
                .ok_or_else(|| TestCaseError::fail("schemas not an object"))?;
            prop_assert!(schemas.contains_key("CreateChallengeRequest"));
            prop_assert!(schemas.contains_key("ChallengeResponse"));
            prop_assert!(schemas.contains_key("ChallengeDetailsResponse"));
            prop_assert!(schemas.contains_key("SubmitProofRequest"));
            prop_assert!(schemas.contains_key("VerifyResponse"));
            prop_assert!(schemas.contains_key("RedeemRequest"));
            prop_assert!(schemas.contains_key("RedeemResponse"));
            prop_assert!(schemas.contains_key("ChallengeStatus"));
            prop_assert!(schemas.contains_key("ErrorResponse"));
            prop_assert!(schemas.contains_key("HealthCheckResponse"));
            prop_assert!(schemas.contains_key("CspReport"));
        }

        /// Property: Title is always consistent
        #[test]
        fn prop_title_consistent(
            version in "[0-9]+\\.[0-9]+\\.[0-9]+",
            base_url in "https://[a-z]{3,10}\\.com"
        ) {
            let spec = generate_spec(&version, &base_url);
            prop_assert_eq!(spec["info"]["title"].as_str(), Some("Provii Verifier API"));
        }

        /// Property: Tags array always has 7 elements
        #[test]
        fn prop_tags_count_constant(
            version in "[0-9]+\\.[0-9]+\\.[0-9]+",
            base_url in "https://[a-z]{3,10}\\.com"
        ) {
            let spec = generate_spec(&version, &base_url);
            let tags = spec["tags"].as_array()
                .ok_or_else(|| TestCaseError::fail("tags not an array"))?;
            prop_assert_eq!(tags.len(), 6);
        }

        /// Property: Servers array always has 1 element
        #[test]
        fn prop_servers_count_constant(
            version in "[0-9]+\\.[0-9]+\\.[0-9]+",
            base_url in "https://[a-z]{3,10}\\.com"
        ) {
            let spec = generate_spec(&version, &base_url);
            let servers = spec["servers"].as_array()
                .ok_or_else(|| TestCaseError::fail("servers not an array"))?;
            prop_assert_eq!(servers.len(), 1);
        }
    }

    // ========================================================================
    // strip_schema_keyword Tests
    // ========================================================================

    #[test]
    fn test_strip_schema_keyword_removes_top_level_schema() {
        let mut val = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object"
        });
        strip_schema_keyword(&mut val);
        assert!(val.get("$schema").is_none());
        assert_eq!(val["type"], "object");
    }

    #[test]
    fn test_strip_schema_keyword_removes_nested_schema() {
        let mut val = json!({
            "properties": {
                "name": {
                    "$schema": "http://json-schema.org/draft-07/schema#",
                    "type": "string"
                }
            }
        });
        strip_schema_keyword(&mut val);
        assert!(val["properties"]["name"].get("$schema").is_none());
        assert_eq!(val["properties"]["name"]["type"], "string");
    }

    #[test]
    fn test_strip_schema_keyword_removes_deeply_nested() {
        let mut val = json!({
            "a": {
                "b": {
                    "c": {
                        "$schema": "draft-07",
                        "type": "integer"
                    }
                }
            }
        });
        strip_schema_keyword(&mut val);
        assert!(val["a"]["b"]["c"].get("$schema").is_none());
        assert_eq!(val["a"]["b"]["c"]["type"], "integer");
    }

    #[test]
    fn test_strip_schema_keyword_recurses_into_arrays() {
        let mut val = json!([
            { "$schema": "draft-07", "type": "string" },
            { "$schema": "draft-07", "type": "integer" }
        ]);
        strip_schema_keyword(&mut val);
        let arr = val.as_array().expect("test: known array");
        assert!(arr[0].get("$schema").is_none());
        assert!(arr[1].get("$schema").is_none());
    }

    #[test]
    fn test_strip_schema_keyword_mixed_array_and_object() {
        let mut val = json!({
            "oneOf": [
                { "$schema": "s", "type": "string" },
                { "properties": { "x": { "$schema": "s", "type": "number" } } }
            ]
        });
        strip_schema_keyword(&mut val);
        assert!(val["oneOf"][0].get("$schema").is_none());
        assert!(val["oneOf"][1]["properties"]["x"].get("$schema").is_none());
    }

    #[test]
    fn test_strip_schema_keyword_no_op_on_string() {
        let mut val = json!("hello");
        strip_schema_keyword(&mut val);
        assert_eq!(val, json!("hello"));
    }

    #[test]
    fn test_strip_schema_keyword_no_op_on_number() {
        let mut val = json!(42);
        strip_schema_keyword(&mut val);
        assert_eq!(val, json!(42));
    }

    #[test]
    fn test_strip_schema_keyword_no_op_on_bool() {
        let mut val = json!(true);
        strip_schema_keyword(&mut val);
        assert_eq!(val, json!(true));
    }

    #[test]
    fn test_strip_schema_keyword_no_op_on_null() {
        let mut val = json!(null);
        strip_schema_keyword(&mut val);
        assert_eq!(val, json!(null));
    }

    #[test]
    fn test_strip_schema_keyword_empty_object() {
        let mut val = json!({});
        strip_schema_keyword(&mut val);
        assert_eq!(val, json!({}));
    }

    #[test]
    fn test_strip_schema_keyword_empty_array() {
        let mut val = json!([]);
        strip_schema_keyword(&mut val);
        assert_eq!(val, json!([]));
    }

    #[test]
    fn test_strip_schema_keyword_preserves_other_keys() {
        let mut val = json!({
            "$schema": "draft-07",
            "type": "object",
            "description": "A thing",
            "required": ["a"]
        });
        strip_schema_keyword(&mut val);
        assert!(val.get("$schema").is_none());
        assert_eq!(val["type"], "object");
        assert_eq!(val["description"], "A thing");
        assert!(val["required"].is_array());
    }

    #[test]
    fn test_strip_schema_keyword_multiple_schema_keys_at_different_depths() {
        let mut val = json!({
            "$schema": "root",
            "definitions": {
                "Foo": {
                    "$schema": "nested",
                    "items": [
                        { "$schema": "array-item" }
                    ]
                }
            }
        });
        strip_schema_keyword(&mut val);
        assert!(val.get("$schema").is_none());
        assert!(val["definitions"]["Foo"].get("$schema").is_none());
        assert!(val["definitions"]["Foo"]["items"][0]
            .get("$schema")
            .is_none());
    }

    // ========================================================================
    // strip_private_paths Tests
    // ========================================================================

    #[test]
    fn test_strip_private_paths_removes_sandbox_tagged() {
        let spec = json!({
            "paths": {
                "/public": {
                    "get": { "tags": ["Challenge"] }
                },
                "/sandbox-only": {
                    "post": { "tags": ["Sandbox"] }
                }
            }
        });
        let result = strip_private_paths(spec);
        let paths = result["paths"].as_object().expect("test: known object");
        assert!(paths.contains_key("/public"));
        assert!(!paths.contains_key("/sandbox-only"));
    }

    #[test]
    fn test_strip_private_paths_removes_internal_tagged() {
        let spec = json!({
            "paths": {
                "/public": {
                    "get": { "tags": ["Meta"] }
                },
                "/internal-only": {
                    "get": { "tags": ["Internal"] }
                }
            }
        });
        let result = strip_private_paths(spec);
        let paths = result["paths"].as_object().expect("test: known object");
        assert!(paths.contains_key("/public"));
        assert!(!paths.contains_key("/internal-only"));
    }

    #[test]
    fn test_strip_private_paths_retains_all_public() {
        let spec = json!({
            "paths": {
                "/a": { "get": { "tags": ["Challenge"] } },
                "/b": { "post": { "tags": ["Verification"] } },
                "/c": { "get": { "tags": ["Operations"] } }
            }
        });
        let result = strip_private_paths(spec);
        let paths = result["paths"].as_object().expect("test: known object");
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn test_strip_private_paths_removes_when_any_method_is_private() {
        let spec = json!({
            "paths": {
                "/mixed": {
                    "get": { "tags": ["Challenge"] },
                    "post": { "tags": ["Sandbox"] }
                }
            }
        });
        let result = strip_private_paths(spec);
        let paths = result["paths"].as_object().expect("test: known object");
        // Path is removed because at least one method has a private tag.
        assert!(!paths.contains_key("/mixed"));
    }

    #[test]
    fn test_strip_private_paths_empty_paths() {
        let spec = json!({ "paths": {} });
        let result = strip_private_paths(spec);
        let paths = result["paths"].as_object().expect("test: known object");
        assert!(paths.is_empty());
    }

    #[test]
    fn test_strip_private_paths_no_paths_key() {
        let spec = json!({ "info": { "title": "test" } });
        let result = strip_private_paths(spec);
        // Should not panic; paths key is simply absent.
        assert!(result["info"]["title"].is_string());
    }

    #[test]
    fn test_strip_private_paths_method_without_tags() {
        let spec = json!({
            "paths": {
                "/no-tags": {
                    "get": { "summary": "No tags here" }
                }
            }
        });
        let result = strip_private_paths(spec);
        let paths = result["paths"].as_object().expect("test: known object");
        // No tags means not private; path is retained.
        assert!(paths.contains_key("/no-tags"));
    }

    #[test]
    fn test_strip_private_paths_method_with_empty_tags() {
        let spec = json!({
            "paths": {
                "/empty-tags": {
                    "get": { "tags": [] }
                }
            }
        });
        let result = strip_private_paths(spec);
        let paths = result["paths"].as_object().expect("test: known object");
        assert!(paths.contains_key("/empty-tags"));
    }

    #[test]
    fn test_strip_private_paths_preserves_non_path_keys() {
        let spec = json!({
            "openapi": "3.1.0",
            "info": { "title": "test" },
            "paths": {
                "/secret": { "get": { "tags": ["Internal"] } }
            },
            "components": { "schemas": {} }
        });
        let result = strip_private_paths(spec);
        assert_eq!(result["openapi"], "3.1.0");
        assert_eq!(result["info"]["title"], "test");
        assert!(result["components"]["schemas"].is_object());
    }

    #[test]
    fn test_strip_private_paths_non_object_method_value_retained() {
        // Edge case: a path whose value is not a JSON object (malformed).
        // The function treats non-object values as "keep" (the else branch).
        let spec = json!({
            "paths": {
                "/weird": "not an object"
            }
        });
        let result = strip_private_paths(spec);
        let paths = result["paths"].as_object().expect("test: known object");
        assert!(paths.contains_key("/weird"));
    }

    #[test]
    fn test_strip_private_paths_multiple_private_tags() {
        let spec = json!({
            "paths": {
                "/a": { "get": { "tags": ["Internal", "Sandbox"] } },
                "/b": { "get": { "tags": ["Challenge"] } }
            }
        });
        let result = strip_private_paths(spec);
        let paths = result["paths"].as_object().expect("test: known object");
        assert!(!paths.contains_key("/a"));
        assert!(paths.contains_key("/b"));
    }

    #[test]
    fn test_strip_private_paths_tag_value_not_string() {
        // Edge case: tag is not a string (e.g., a number).
        let spec = json!({
            "paths": {
                "/num-tag": {
                    "get": { "tags": [42] }
                }
            }
        });
        let result = strip_private_paths(spec);
        let paths = result["paths"].as_object().expect("test: known object");
        // Non-string tag cannot match PRIVATE_TAGS, so path is retained.
        assert!(paths.contains_key("/num-tag"));
    }

    // ========================================================================
    // PRIVATE_TAGS Constant Tests
    // ========================================================================

    #[test]
    fn test_private_tags_contains_internal() {
        assert!(PRIVATE_TAGS.contains(&"Internal"));
    }

    #[test]
    fn test_private_tags_contains_sandbox() {
        assert!(PRIVATE_TAGS.contains(&"Sandbox"));
    }

    #[test]
    fn test_private_tags_count() {
        assert_eq!(PRIVATE_TAGS.len(), 2);
    }

    #[test]
    fn test_private_tags_does_not_contain_challenge() {
        assert!(!PRIVATE_TAGS.contains(&"Challenge"));
    }

    #[test]
    fn test_private_tags_does_not_contain_operations() {
        assert!(!PRIVATE_TAGS.contains(&"Operations"));
    }

    // ========================================================================
    // generate_spec: base_url /v1 suffix stripping (XA3-1)
    // ========================================================================

    #[test]
    fn test_generate_spec_strips_v1_suffix_from_base_url() {
        let spec = generate_spec("1.0.0", "https://verify.provii.app/v1");
        assert_eq!(spec["servers"][0]["url"], "https://verify.provii.app");
    }

    #[test]
    fn test_generate_spec_does_not_strip_v1_in_middle() {
        let spec = generate_spec("1.0.0", "https://v1.example.com");
        assert_eq!(spec["servers"][0]["url"], "https://v1.example.com");
    }

    #[test]
    fn test_generate_spec_does_not_strip_v1_with_trailing_slash() {
        // trim_end_matches only strips exact "/v1", not "/v1/".
        let spec = generate_spec("1.0.0", "https://example.com/v1/");
        // "/v1/" does not end with exactly "/v1" (it ends with "/"), so no stripping.
        assert_eq!(spec["servers"][0]["url"], "https://example.com/v1/");
    }

    #[test]
    fn test_generate_spec_strips_v1_suffix_preserves_path() {
        let spec = generate_spec("1.0.0", "https://api.example.com/api/v1");
        assert_eq!(spec["servers"][0]["url"], "https://api.example.com/api");
    }

    // ========================================================================
    // generate_spec: Simulate Proof Path
    // ========================================================================

    #[test]
    fn test_generate_spec_simulate_proof_path() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/hosted/sandbox/simulate-proof"]["post"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "simulateProof");
    }

    #[test]
    fn test_generate_spec_simulate_proof_tags() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["paths"]["/v1/hosted/sandbox/simulate-proof"]["post"]["tags"]
            .as_array()
            .ok_or("tags not an array")?;
        assert!(tags.contains(&json!("Sandbox")));
        Ok(())
    }

    #[test]
    fn test_generate_spec_simulate_proof_responses() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let responses = &spec["paths"]["/v1/hosted/sandbox/simulate-proof"]["post"]["responses"];
        assert!(responses["200"].is_object());
        assert!(responses["400"].is_object());
        assert!(responses["403"].is_object());
        assert!(responses["404"].is_object());
        assert!(responses["410"].is_object());
        assert!(responses["500"].is_object());
    }

    // ========================================================================
    // generate_spec: Security Arrays Per Path
    // ========================================================================

    #[test]
    fn test_generate_spec_challenge_requires_api_key() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let security = spec["paths"]["/v1/challenge"]["post"]["security"]
            .as_array()
            .ok_or("security not an array")?;
        assert!(!security.is_empty());
        assert!(security[0].get("ApiKeyAuth").is_some());
        Ok(())
    }

    #[test]
    fn test_generate_spec_poll_challenge_no_security() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let security = &spec["paths"]["/v1/challenge/{session_id}"]["get"]["security"];
        assert!(security.is_array());
        assert_eq!(security.as_array().map(|a| a.len()), Some(0));
    }

    #[test]
    fn test_generate_spec_redeem_no_security() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let security = &spec["paths"]["/v1/challenge/{session_id}/redeem"]["post"]["security"];
        assert!(security.is_array());
        assert_eq!(security.as_array().map(|a| a.len()), Some(0));
    }

    #[test]
    fn test_generate_spec_verify_no_security() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let security = &spec["paths"]["/v1/verify"]["post"]["security"];
        assert!(security.is_array());
        assert_eq!(security.as_array().map(|a| a.len()), Some(0));
    }

    #[test]
    fn test_generate_spec_health_no_security() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let security = &spec["paths"]["/health"]["get"]["security"];
        assert!(security.is_array());
        assert_eq!(security.as_array().map(|a| a.len()), Some(0));
    }

    #[test]
    fn test_generate_spec_register_test_origin_requires_api_key(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let security = spec["paths"]["/v1/register-test-origin"]["post"]["security"]
            .as_array()
            .ok_or("security not an array")?;
        assert!(!security.is_empty());
        assert!(security[0].get("ApiKeyAuth").is_some());
        Ok(())
    }

    #[test]
    fn test_generate_spec_simulate_proof_no_security() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let security = &spec["paths"]["/v1/hosted/sandbox/simulate-proof"]["post"]["security"];
        assert!(security.is_array());
        assert_eq!(security.as_array().map(|a| a.len()), Some(0));
    }

    // ========================================================================
    // generate_spec: ApiKeyAuth Security Scheme Details
    // ========================================================================

    #[test]
    fn test_api_key_auth_scheme_type() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert_eq!(
            spec["components"]["securitySchemes"]["ApiKeyAuth"]["type"],
            "apiKey"
        );
    }

    #[test]
    fn test_api_key_auth_scheme_in_header() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert_eq!(
            spec["components"]["securitySchemes"]["ApiKeyAuth"]["in"],
            "header"
        );
    }

    #[test]
    fn test_api_key_auth_scheme_name() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert_eq!(
            spec["components"]["securitySchemes"]["ApiKeyAuth"]["name"],
            "X-API-Key"
        );
    }

    #[test]
    fn test_api_key_auth_scheme_has_description() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["components"]["securitySchemes"]["ApiKeyAuth"]["description"].is_string());
    }

    // ========================================================================
    // generate_spec: Hand-Written Schema Definitions
    // ========================================================================

    #[test]
    fn test_schema_health_check_response_properties() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let schema = &spec["components"]["schemas"]["HealthCheckResponse"];
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["status"].is_object());
        assert!(schema["properties"]["timestamp"].is_object());
        assert!(schema["properties"]["version"].is_object());
        assert!(schema["properties"]["checks"].is_object());
    }

    #[test]
    fn test_schema_health_check_response_status_enum() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let enum_vals = spec["components"]["schemas"]["HealthCheckResponse"]["properties"]
            ["status"]["enum"]
            .as_array()
            .ok_or("enum not an array")?;
        assert!(enum_vals.contains(&json!("healthy")));
        assert!(enum_vals.contains(&json!("degraded")));
        assert!(enum_vals.contains(&json!("unhealthy")));
        Ok(())
    }

    #[test]
    fn test_schema_health_check_response_checks_subsystems() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let checks = &spec["components"]["schemas"]["HealthCheckResponse"]["properties"]["checks"]
            ["properties"];
        assert!(checks["challenge_store"].is_object());
        assert!(checks["nonce_store"].is_object());
        assert!(checks["jwks_cache"].is_object());
        assert!(checks["rate_limiter"].is_object());
        assert!(checks["ban_store"].is_object());
    }

    #[test]
    fn test_schema_subsystem_health_structure() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let schema = &spec["components"]["schemas"]["SubsystemHealth"];
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["operational"].is_object());
        assert!(schema["properties"]["message"].is_object());
        assert!(schema["properties"]["metrics"].is_object());
    }

    #[test]
    fn test_schema_subsystem_health_required_fields() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let required = spec["components"]["schemas"]["SubsystemHealth"]["required"]
            .as_array()
            .ok_or("required not an array")?;
        assert!(required.contains(&json!("operational")));
        Ok(())
    }

    #[test]
    fn test_schema_csp_report_structure() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let schema = &spec["components"]["schemas"]["CspReport"];
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["csp-report"].is_object());
    }

    #[test]
    fn test_schema_csp_report_required_field() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let required = spec["components"]["schemas"]["CspReport"]["required"]
            .as_array()
            .ok_or("required not an array")?;
        assert!(required.contains(&json!("csp-report")));
        Ok(())
    }

    #[test]
    fn test_schema_csp_report_nested_properties() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let props =
            &spec["components"]["schemas"]["CspReport"]["properties"]["csp-report"]["properties"];
        assert!(props["document-uri"].is_object());
        assert!(props["blocked-uri"].is_object());
        assert!(props["violated-directive"].is_object());
        assert!(props["effective-directive"].is_object());
        assert!(props["status-code"].is_object());
    }

    #[test]
    fn test_schema_register_test_origin_request_structure() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let schema = &spec["components"]["schemas"]["RegisterTestOriginRequest"];
        assert_eq!(schema["type"], "object");
    }

    #[test]
    fn test_schema_register_test_origin_request_required_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let required = spec["components"]["schemas"]["RegisterTestOriginRequest"]["required"]
            .as_array()
            .ok_or("required not an array")?;
        assert!(required.contains(&json!("origin")));
        assert!(required.contains(&json!("api_key")));
        Ok(())
    }

    #[test]
    fn test_schema_register_test_origin_request_properties() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let props = &spec["components"]["schemas"]["RegisterTestOriginRequest"]["properties"];
        assert!(props["origin"].is_object());
        assert!(props["min_age_years"].is_object());
        assert!(props["api_key"].is_object());
        assert!(props["contact_email"].is_object());
        assert!(props["proof_direction"].is_object());
        assert!(props["max_age_years"].is_object());
    }

    #[test]
    fn test_schema_register_test_origin_request_min_age_constraints() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let min_age = &spec["components"]["schemas"]["RegisterTestOriginRequest"]["properties"]
            ["min_age_years"];
        assert_eq!(min_age["type"], "integer");
        assert_eq!(min_age["default"], 18);
        assert_eq!(min_age["minimum"], 0);
        assert_eq!(min_age["maximum"], 150);
    }

    #[test]
    fn test_schema_register_test_origin_request_proof_direction_enum(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let enum_vals = spec["components"]["schemas"]["RegisterTestOriginRequest"]["properties"]
            ["proof_direction"]["enum"]
            .as_array()
            .ok_or("enum not an array")?;
        assert!(enum_vals.contains(&json!("over_age")));
        assert!(enum_vals.contains(&json!("under_age")));
        assert_eq!(enum_vals.len(), 2);
        Ok(())
    }

    #[test]
    fn test_schema_register_test_origin_response_properties() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let props = &spec["components"]["schemas"]["RegisterTestOriginResponse"]["properties"];
        assert!(props["success"].is_object());
        assert!(props["message"].is_object());
        assert!(props["origin"].is_object());
        assert!(props["hmac_secret"].is_object());
        assert!(props["client_id"].is_object());
        assert!(props["security_note"].is_object());
        assert!(props["expires_at"].is_object());
        assert!(props["ttl_seconds"].is_object());
        assert!(props["already_existed"].is_object());
        assert!(props["test_instructions"].is_object());
    }

    #[test]
    fn test_schema_simulate_proof_request_required_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let required = spec["components"]["schemas"]["SimulateProofRequest"]["required"]
            .as_array()
            .ok_or("required not an array")?;
        assert!(required.contains(&json!("challenge_id")));
        assert!(required.contains(&json!("submit_secret")));
        assert!(required.contains(&json!("outcome")));
        assert_eq!(required.len(), 3);
        Ok(())
    }

    #[test]
    fn test_schema_simulate_proof_request_properties() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let props = &spec["components"]["schemas"]["SimulateProofRequest"]["properties"];
        assert_eq!(props["challenge_id"]["format"], "uuid");
        assert_eq!(props["challenge_id"]["type"], "string");
        assert_eq!(props["submit_secret"]["type"], "string");
    }

    #[test]
    fn test_schema_simulate_proof_request_outcome_enum() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let enum_vals = spec["components"]["schemas"]["SimulateProofRequest"]["properties"]
            ["outcome"]["enum"]
            .as_array()
            .ok_or("enum not an array")?;
        assert!(enum_vals.contains(&json!("verified")));
        assert!(enum_vals.contains(&json!("age_not_met")));
        assert_eq!(enum_vals.len(), 2);
        Ok(())
    }

    #[test]
    fn test_schema_simulate_proof_response_required_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let required = spec["components"]["schemas"]["SimulateProofResponse"]["required"]
            .as_array()
            .ok_or("required not an array")?;
        assert!(required.contains(&json!("result")));
        assert!(required.contains(&json!("state")));
        assert_eq!(required.len(), 2);
        Ok(())
    }

    #[test]
    fn test_schema_simulate_proof_response_properties() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let props = &spec["components"]["schemas"]["SimulateProofResponse"]["properties"];
        assert_eq!(props["result"]["type"], "string");
        assert_eq!(props["state"]["type"], "string");
    }

    // ========================================================================
    // generate_spec: Derived Schema Validation (from schemars)
    // ========================================================================

    #[test]
    fn test_schema_challenge_details_response_exists() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["components"]["schemas"]["ChallengeDetailsResponse"].is_object());
    }

    // ========================================================================
    // generate_spec: Challenge Path Response Details
    // ========================================================================

    #[test]
    fn test_challenge_path_201_has_content_type() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let content = &spec["paths"]["/v1/challenge"]["post"]["responses"]["201"]["content"];
        assert!(content["application/json"].is_object());
    }

    #[test]
    fn test_challenge_path_429_has_retry_after_header() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let headers = &spec["paths"]["/v1/challenge"]["post"]["responses"]["429"]["headers"];
        assert!(headers["Retry-After"].is_object());
        assert_eq!(headers["Retry-After"]["schema"]["type"], "integer");
    }

    #[test]
    fn test_challenge_path_error_responses_reference_error_schema() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let responses = &spec["paths"]["/v1/challenge"]["post"]["responses"];
        for code in &["400", "403", "500"] {
            let schema_ref = &responses[*code]["content"]["application/json"]["schema"]["$ref"];
            assert_eq!(schema_ref, "#/components/schemas/ErrorResponse");
        }
    }

    // ========================================================================
    // generate_spec: Poll Challenge Response Details
    // ========================================================================

    #[test]
    fn test_poll_challenge_200_has_schema() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let content = &spec["paths"]["/v1/challenge/{session_id}"]["get"]["responses"]["200"]
            ["content"]["application/json"];
        assert!(content["schema"].is_object());
    }

    #[test]
    fn test_poll_challenge_404_response() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"]["/v1/challenge/{session_id}"]["get"]["responses"]["404"].is_object());
    }

    #[test]
    fn test_poll_challenge_410_response() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"]["/v1/challenge/{session_id}"]["get"]["responses"]["410"].is_object());
    }

    // ========================================================================
    // generate_spec: Redeem Path Details
    // ========================================================================

    #[test]
    fn test_redeem_path_has_request_body() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let req_body = &spec["paths"]["/v1/challenge/{session_id}/redeem"]["post"]["requestBody"];
        assert!(req_body.is_object());
        assert_eq!(req_body["required"], true);
    }

    #[test]
    fn test_redeem_path_session_id_param() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let params = spec["paths"]["/v1/challenge/{session_id}/redeem"]["post"]["parameters"]
            .as_array()
            .ok_or("parameters not an array")?;
        let sid = params
            .iter()
            .find(|p| p["name"] == "session_id")
            .ok_or("session_id param not found")?;
        assert_eq!(sid["in"], "path");
        assert_eq!(sid["required"], true);
        assert_eq!(sid["schema"]["format"], "uuid");
        Ok(())
    }

    // ========================================================================
    // generate_spec: Verify Path Details
    // ========================================================================

    #[test]
    fn test_verify_path_has_request_body() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let req_body = &spec["paths"]["/v1/verify"]["post"]["requestBody"];
        assert!(req_body.is_object());
        assert_eq!(req_body["required"], true);
        assert!(req_body["content"]["application/json"].is_object());
    }

    #[test]
    fn test_verify_path_tags() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["paths"]["/v1/verify"]["post"]["tags"]
            .as_array()
            .ok_or("tags not an array")?;
        assert!(tags.contains(&json!("Verification")));
        Ok(())
    }

    // ========================================================================
    // generate_spec: Health Path Details
    // ========================================================================

    #[test]
    fn test_health_200_response_schema_properties() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let schema = &spec["paths"]["/health"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"];
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["status"].is_object());
        assert!(schema["properties"]["timestamp"].is_object());
        assert!(schema["properties"]["version"].is_object());
    }

    #[test]
    fn test_health_200_response_required_fields() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let required = spec["paths"]["/health"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["required"]
            .as_array()
            .ok_or("required not an array")?;
        assert!(required.contains(&json!("status")));
        assert!(required.contains(&json!("timestamp")));
        assert!(required.contains(&json!("version")));
        Ok(())
    }

    #[test]
    fn test_health_503_response() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let resp = &spec["paths"]["/health"]["get"]["responses"]["503"];
        assert!(resp.is_object());
        assert!(resp["content"]["application/json"]["schema"].is_object());
    }

    #[test]
    fn test_health_tags() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["paths"]["/health"]["get"]["tags"]
            .as_array()
            .ok_or("tags not an array")?;
        assert!(tags.contains(&json!("System")));
        Ok(())
    }

    // ========================================================================
    // generate_spec: Detailed Health Path Details
    // ========================================================================

    #[test]
    fn test_health_detailed_200_references_health_check_response() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let schema_ref = &spec["paths"]["/health/detailed"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["$ref"];
        assert_eq!(schema_ref, "#/components/schemas/HealthCheckResponse");
    }

    #[test]
    fn test_health_detailed_503_response() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"]["/health/detailed"]["get"]["responses"]["503"].is_object());
    }

    #[test]
    fn test_health_detailed_500_response() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"]["/health/detailed"]["get"]["responses"]["500"].is_object());
    }

    // ========================================================================
    // generate_spec: Metrics Path Details
    // ========================================================================

    #[test]
    fn test_metrics_200_content_type() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let content = &spec["paths"]["/metrics"]["get"]["responses"]["200"]["content"];
        assert!(content["text/plain"].is_object());
    }

    #[test]
    fn test_metrics_500_response() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"]["/metrics"]["get"]["responses"]["500"].is_object());
    }

    #[test]
    fn test_metrics_tags() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["paths"]["/metrics"]["get"]["tags"]
            .as_array()
            .ok_or("tags not an array")?;
        assert!(tags.contains(&json!("Operations")));
        Ok(())
    }

    // ========================================================================
    // generate_spec: CSP Report Path Details
    // ========================================================================

    #[test]
    fn test_csp_report_content_type() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let content = &spec["paths"]["/v1/csp-report"]["post"]["requestBody"]["content"];
        assert!(content["application/csp-report"].is_object());
    }

    #[test]
    fn test_csp_report_references_csp_report_schema() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let schema_ref = &spec["paths"]["/v1/csp-report"]["post"]["requestBody"]["content"]
            ["application/csp-report"]["schema"]["$ref"];
        assert_eq!(schema_ref, "#/components/schemas/CspReport");
    }

    #[test]
    fn test_csp_report_tags() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["paths"]["/v1/csp-report"]["post"]["tags"]
            .as_array()
            .ok_or("tags not an array")?;
        assert!(tags.contains(&json!("Meta")));
        Ok(())
    }

    #[test]
    fn test_csp_report_500_response() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert!(spec["paths"]["/v1/csp-report"]["post"]["responses"]["500"].is_object());
    }

    // ========================================================================
    // generate_spec: OpenAPI JSON Self-Referential Path Details
    // ========================================================================

    #[test]
    fn test_openapi_json_path_tags() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["paths"]["/v1/openapi.json"]["get"]["tags"]
            .as_array()
            .ok_or("tags not an array")?;
        assert!(tags.contains(&json!("Meta")));
        Ok(())
    }

    #[test]
    fn test_openapi_json_path_200_content_type() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let content = &spec["paths"]["/v1/openapi.json"]["get"]["responses"]["200"]["content"];
        assert!(content["application/json"].is_object());
    }

    // ========================================================================
    // generate_spec: Docs Path Details
    // ========================================================================

    #[test]
    fn test_docs_path_tags() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["paths"]["/v1/docs"]["get"]["tags"]
            .as_array()
            .ok_or("tags not an array")?;
        assert!(tags.contains(&json!("Meta")));
        Ok(())
    }

    #[test]
    fn test_docs_path_200_content_type() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let content = &spec["paths"]["/v1/docs"]["get"]["responses"]["200"]["content"];
        assert!(content["text/html"].is_object());
    }

    // ========================================================================
    // generate_spec: Challenge Details Path Details
    // ========================================================================

    #[test]
    fn test_challenge_details_tags() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["paths"]["/v1/challenge/{session_id}/details"]["get"]["tags"]
            .as_array()
            .ok_or("tags not an array")?;
        assert!(tags.contains(&json!("Challenge")));
        Ok(())
    }

    #[test]
    fn test_challenge_details_session_id_param() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let params = spec["paths"]["/v1/challenge/{session_id}/details"]["get"]["parameters"]
            .as_array()
            .ok_or("parameters not an array")?;
        let sid = params
            .iter()
            .find(|p| p["name"] == "session_id")
            .ok_or("session_id param not found")?;
        assert_eq!(sid["in"], "path");
        assert_eq!(sid["required"], true);
        assert_eq!(sid["schema"]["format"], "uuid");
        Ok(())
    }

    #[test]
    fn test_challenge_details_responses() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let responses = &spec["paths"]["/v1/challenge/{session_id}/details"]["get"]["responses"];
        assert!(responses["200"].is_object());
        assert!(responses["404"].is_object());
        assert!(responses["410"].is_object());
        assert!(responses["500"].is_object());
    }

    // ========================================================================
    // generate_spec: Challenge By Code Path Details
    // ========================================================================

    #[test]
    fn test_challenge_by_code_tags() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["paths"]["/v1/challenge/by-code/{code}"]["get"]["tags"]
            .as_array()
            .ok_or("tags not an array")?;
        assert!(tags.contains(&json!("Challenge")));
        Ok(())
    }

    #[test]
    fn test_challenge_by_code_param() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let params = spec["paths"]["/v1/challenge/by-code/{code}"]["get"]["parameters"]
            .as_array()
            .ok_or("parameters not an array")?;
        let code = params
            .iter()
            .find(|p| p["name"] == "code")
            .ok_or("code param not found")?;
        assert_eq!(code["in"], "path");
        assert_eq!(code["required"], true);
        assert_eq!(code["schema"]["type"], "string");
        Ok(())
    }

    #[test]
    fn test_challenge_by_code_responses() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let responses = &spec["paths"]["/v1/challenge/by-code/{code}"]["get"]["responses"];
        assert!(responses["200"].is_object());
        assert!(responses["404"].is_object());
        assert!(responses["410"].is_object());
        assert!(responses["500"].is_object());
    }

    // ========================================================================
    // generate_spec: Register Test Origin Path Details
    // ========================================================================

    #[test]
    fn test_register_test_origin_request_body() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let req_body = &spec["paths"]["/v1/register-test-origin"]["post"]["requestBody"];
        assert_eq!(req_body["required"], true);
        let schema_ref = &req_body["content"]["application/json"]["schema"]["$ref"];
        assert_eq!(schema_ref, "#/components/schemas/RegisterTestOriginRequest");
    }

    #[test]
    fn test_register_test_origin_responses() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let responses = &spec["paths"]["/v1/register-test-origin"]["post"]["responses"];
        assert!(responses["200"].is_object());
        assert!(responses["400"].is_object());
        assert!(responses["403"].is_object());
        assert!(responses["429"].is_object());
        assert!(responses["500"].is_object());
    }

    #[test]
    fn test_register_test_origin_429_has_retry_after() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let headers =
            &spec["paths"]["/v1/register-test-origin"]["post"]["responses"]["429"]["headers"];
        assert!(headers["Retry-After"].is_object());
    }

    // ========================================================================
    // generate_spec: Simulate Proof Request Body Details
    // ========================================================================

    #[test]
    fn test_simulate_proof_request_body() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let req_body = &spec["paths"]["/v1/hosted/sandbox/simulate-proof"]["post"]["requestBody"];
        assert_eq!(req_body["required"], true);
        let schema_ref = &req_body["content"]["application/json"]["schema"]["$ref"];
        assert_eq!(schema_ref, "#/components/schemas/SimulateProofRequest");
    }

    // ========================================================================
    // strip_private_paths integration with generate_spec
    // ========================================================================

    #[test]
    fn test_strip_private_paths_removes_sandbox_from_generated_spec() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        // Before stripping, sandbox paths exist.
        assert!(spec["paths"]["/v1/register-test-origin"].is_object());
        assert!(spec["paths"]["/v1/hosted/sandbox/simulate-proof"].is_object());

        let stripped = strip_private_paths(spec);
        let paths = stripped["paths"].as_object().expect("test: known object");
        // After stripping, sandbox-tagged paths are gone.
        assert!(!paths.contains_key("/v1/register-test-origin"));
        assert!(!paths.contains_key("/v1/hosted/sandbox/simulate-proof"));
    }

    #[test]
    fn test_strip_private_paths_retains_public_from_generated_spec() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let stripped = strip_private_paths(spec);
        let paths = stripped["paths"].as_object().expect("test: known object");
        assert!(paths.contains_key("/v1/challenge"));
        assert!(paths.contains_key("/v1/challenge/{session_id}"));
        assert!(paths.contains_key("/v1/challenge/{session_id}/redeem"));
        assert!(paths.contains_key("/v1/verify"));
        assert!(paths.contains_key("/health"));
        assert!(paths.contains_key("/health/detailed"));
        assert!(paths.contains_key("/metrics"));
        assert!(paths.contains_key("/v1/csp-report"));
        assert!(paths.contains_key("/v1/openapi.json"));
        assert!(paths.contains_key("/v1/docs"));
    }

    // ========================================================================
    // strip_schema_keyword integration with generate_spec
    // ========================================================================

    #[test]
    fn test_strip_schema_keyword_on_generated_spec() -> Result<(), Box<dyn std::error::Error>> {
        let mut spec = generate_spec("1.0.0", "https://api.example.com");
        strip_schema_keyword(&mut spec);
        // After stripping, no $schema key should remain anywhere.
        let json_str = serde_json::to_string(&spec)?;
        assert!(!json_str.contains("\"$schema\""));
        Ok(())
    }

    // ========================================================================
    // ChallengeStatus JSON Schema via schemars
    // ========================================================================

    #[test]
    fn test_challenge_status_json_schema_type() {
        let schema = schema_for!(ChallengeStatus);
        let val = serde_json::to_value(&schema).expect("test: known serialisable");
        assert_eq!(val["type"], "object");
    }

    #[test]
    fn test_challenge_status_json_schema_has_properties() {
        let schema = schema_for!(ChallengeStatus);
        let val = serde_json::to_value(&schema).expect("test: known serialisable");
        assert!(val["properties"]["state"].is_object());
        assert!(val["properties"]["status"].is_object());
        assert!(val["properties"]["verified"].is_object());
        assert!(val["properties"]["proof_verified"].is_object());
    }

    #[test]
    fn test_challenge_status_json_schema_required_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let schema = schema_for!(ChallengeStatus);
        let val = serde_json::to_value(&schema)?;
        let required = val["required"].as_array().ok_or("required not an array")?;
        assert!(required.contains(&json!("state")));
        assert!(required.contains(&json!("status")));
        assert!(required.contains(&json!("verified")));
        assert!(required.contains(&json!("proof_verified")));
        Ok(())
    }

    // ========================================================================
    // ErrorResponse JSON Schema via schemars
    // ========================================================================

    #[test]
    fn test_error_response_json_schema_type() {
        let schema = schema_for!(ErrorResponse);
        let val = serde_json::to_value(&schema).expect("test: known serialisable");
        assert_eq!(val["type"], "object");
    }

    #[test]
    fn test_error_response_json_schema_has_properties() {
        let schema = schema_for!(ErrorResponse);
        let val = serde_json::to_value(&schema).expect("test: known serialisable");
        assert!(val["properties"]["error"].is_object());
        assert!(val["properties"]["request_id"].is_object());
    }

    #[test]
    fn test_error_response_json_schema_required_fields() -> Result<(), Box<dyn std::error::Error>> {
        let schema = schema_for!(ErrorResponse);
        let val = serde_json::to_value(&schema)?;
        let required = val["required"].as_array().ok_or("required not an array")?;
        // error and request_id are required; code is optional (skip_serializing_if).
        assert!(required.contains(&json!("error")));
        assert!(required.contains(&json!("request_id")));
        Ok(())
    }

    // ========================================================================
    // ChallengeStatus Serialization Edge Cases
    // ========================================================================

    #[test]
    fn test_challenge_status_empty_strings() -> Result<(), Box<dyn std::error::Error>> {
        let status = ChallengeStatus {
            state: String::new(),
            status: String::new(),
            verified: false,
            proof_verified: false,
        };
        let json = serde_json::to_value(&status)?;
        assert_eq!(json["state"], "");
        assert_eq!(json["status"], "");
        Ok(())
    }

    #[test]
    fn test_challenge_status_special_characters() -> Result<(), Box<dyn std::error::Error>> {
        let status = ChallengeStatus {
            state: "state with \"quotes\" and \\ backslash".to_string(),
            status: "status/with/slashes".to_string(),
            verified: true,
            proof_verified: false,
        };
        let json_str = serde_json::to_string(&status)?;
        let roundtrip: Value = serde_json::from_str(&json_str)?;
        assert_eq!(roundtrip["state"], "state with \"quotes\" and \\ backslash");
        assert_eq!(roundtrip["status"], "status/with/slashes");
        Ok(())
    }

    #[test]
    fn test_challenge_status_field_count() -> Result<(), Box<dyn std::error::Error>> {
        let status = ChallengeStatus {
            state: "a".to_string(),
            status: "b".to_string(),
            verified: false,
            proof_verified: false,
        };
        let json = serde_json::to_value(&status)?;
        let obj = json.as_object().ok_or("not an object")?;
        assert_eq!(obj.len(), 4);
        Ok(())
    }

    // ========================================================================
    // ErrorResponse Serialization Edge Cases
    // ========================================================================

    #[test]
    fn test_error_response_empty_strings() -> Result<(), Box<dyn std::error::Error>> {
        let err = ErrorResponse {
            error: String::new(),
            code: Some(String::new()),
            request_id: String::new(),
        };
        let json = serde_json::to_value(&err)?;
        assert_eq!(json["error"], "");
        assert_eq!(json["code"], "");
        assert_eq!(json["request_id"], "");
        Ok(())
    }

    #[test]
    fn test_error_response_field_count_with_code() -> Result<(), Box<dyn std::error::Error>> {
        let err = ErrorResponse {
            error: "e".to_string(),
            code: Some("c".to_string()),
            request_id: "r".to_string(),
        };
        let json = serde_json::to_value(&err)?;
        let obj = json.as_object().ok_or("not an object")?;
        assert_eq!(obj.len(), 3);
        Ok(())
    }

    #[test]
    fn test_error_response_field_count_without_code() -> Result<(), Box<dyn std::error::Error>> {
        let err = ErrorResponse {
            error: "e".to_string(),
            code: None,
            request_id: "r".to_string(),
        };
        let json = serde_json::to_value(&err)?;
        let obj = json.as_object().ok_or("not an object")?;
        // code is skipped when None.
        assert_eq!(obj.len(), 2);
        Ok(())
    }

    // ========================================================================
    // generate_spec: Operation IDs Uniqueness
    // ========================================================================

    #[test]
    fn test_all_operation_ids_unique() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let paths = spec["paths"].as_object().ok_or("paths not an object")?;
        let mut op_ids = std::collections::HashSet::new();
        for (_path, methods) in paths {
            if let Some(obj) = methods.as_object() {
                for (_method, details) in obj {
                    if let Some(op_id) = details.get("operationId").and_then(|v| v.as_str()) {
                        assert!(
                            op_ids.insert(op_id.to_string()),
                            "Duplicate operationId: {op_id}"
                        );
                    }
                }
            }
        }
        // Confirm we found a reasonable number of operations.
        assert!(op_ids.len() >= 14);
        Ok(())
    }

    // ========================================================================
    // generate_spec: All Paths Have Valid HTTP Methods
    // ========================================================================

    #[test]
    fn test_all_paths_have_valid_http_methods() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let valid_methods = [
            "get", "post", "put", "delete", "patch", "options", "head", "trace",
        ];
        let paths = spec["paths"].as_object().ok_or("paths not an object")?;
        for (path, methods) in paths {
            if let Some(obj) = methods.as_object() {
                for method in obj.keys() {
                    assert!(
                        valid_methods.contains(&method.as_str()),
                        "Invalid HTTP method '{method}' in path '{path}'"
                    );
                }
            }
        }
        Ok(())
    }

    // ========================================================================
    // generate_spec: All Operations Have Tags
    // ========================================================================

    #[test]
    fn test_all_operations_have_tags() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let paths = spec["paths"].as_object().ok_or("paths not an object")?;
        for (path, methods) in paths {
            if let Some(obj) = methods.as_object() {
                for (method, details) in obj {
                    let tags = details["tags"]
                        .as_array()
                        .ok_or(format!("No tags for {method} {path}"))?;
                    assert!(!tags.is_empty(), "Empty tags array for {method} {path}");
                }
            }
        }
        Ok(())
    }

    // ========================================================================
    // generate_spec: All Operations Have Responses
    // ========================================================================

    #[test]
    fn test_all_operations_have_responses() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let paths = spec["paths"].as_object().ok_or("paths not an object")?;
        for (path, methods) in paths {
            if let Some(obj) = methods.as_object() {
                for (method, details) in obj {
                    assert!(
                        details["responses"].is_object(),
                        "No responses for {method} {path}"
                    );
                    let responses = details["responses"]
                        .as_object()
                        .ok_or(format!("responses not object for {method} {path}"))?;
                    assert!(!responses.is_empty(), "Empty responses for {method} {path}");
                }
            }
        }
        Ok(())
    }

    // ========================================================================
    // generate_spec: All $ref Values Are Valid Component References
    // ========================================================================

    #[test]
    fn test_all_refs_point_to_existing_schemas() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let schemas = spec["components"]["schemas"]
            .as_object()
            .ok_or("schemas not an object")?;

        fn collect_refs(val: &Value, refs: &mut Vec<String>) {
            match val {
                Value::Object(map) => {
                    if let Some(r) = map.get("$ref").and_then(|v| v.as_str()) {
                        refs.push(r.to_string());
                    }
                    for v in map.values() {
                        collect_refs(v, refs);
                    }
                }
                Value::Array(arr) => {
                    for v in arr {
                        collect_refs(v, refs);
                    }
                }
                _ => {}
            }
        }

        let mut refs = Vec::new();
        collect_refs(&spec, &mut refs);

        let prefix = "#/components/schemas/";
        for r in &refs {
            if let Some(name) = r.strip_prefix(prefix) {
                assert!(
                    schemas.contains_key(name),
                    "Dangling $ref: {r} (schema '{name}' not found in components)"
                );
            }
        }
        Ok(())
    }

    // ========================================================================
    // generate_spec: Spec Serialises to Valid JSON
    // ========================================================================

    #[test]
    fn test_generate_spec_pretty_serialisation() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let pretty = serde_json::to_string_pretty(&spec)?;
        let roundtrip: Value = serde_json::from_str(&pretty)?;
        assert_eq!(spec, roundtrip);
        Ok(())
    }

    // ========================================================================
    // generate_spec: Contact Fields
    // ========================================================================

    #[test]
    fn test_contact_url_is_valid_https() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let url = spec["info"]["contact"]["url"]
            .as_str()
            .ok_or("contact url not a string")?;
        assert!(url.starts_with("https://"));
        Ok(())
    }

    #[test]
    fn test_contact_email_contains_at() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let email = spec["info"]["contact"]["email"]
            .as_str()
            .ok_or("contact email not a string")?;
        assert!(email.contains('@'));
        Ok(())
    }

    // ========================================================================
    // generate_spec: Origin Header Example Value
    // ========================================================================

    #[test]
    fn test_challenge_origin_header_example() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let params = spec["paths"]["/v1/challenge"]["post"]["parameters"]
            .as_array()
            .ok_or("parameters not an array")?;
        let origin = params
            .iter()
            .find(|p| p["name"] == "Origin")
            .ok_or("Origin param not found")?;
        assert_eq!(origin["example"], "https://example.com");
        assert_eq!(origin["in"], "header");
        Ok(())
    }

    #[test]
    fn test_challenge_api_key_header_example() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let params = spec["paths"]["/v1/challenge"]["post"]["parameters"]
            .as_array()
            .ok_or("parameters not an array")?;
        let api_key = params
            .iter()
            .find(|p| p["name"] == "X-API-Key")
            .ok_or("X-API-Key param not found")?;
        let example = api_key["example"].as_str().ok_or("example not a string")?;
        assert!(example.starts_with("pk_live_"));
        assert_eq!(api_key["in"], "header");
        Ok(())
    }

    // ========================================================================
    // generate_spec: Health Endpoint Status Enum Values
    // ========================================================================

    #[test]
    fn test_health_200_status_enum_values() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let enum_vals = spec["paths"]["/health"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["properties"]["status"]["enum"]
            .as_array()
            .ok_or("enum not an array")?;
        assert!(enum_vals.contains(&json!("healthy")));
        assert!(enum_vals.contains(&json!("degraded")));
        assert!(enum_vals.contains(&json!("unhealthy")));
        assert_eq!(enum_vals.len(), 3);
        Ok(())
    }

    #[test]
    fn test_health_503_status_enum_values() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let enum_vals = spec["paths"]["/health"]["get"]["responses"]["503"]["content"]
            ["application/json"]["schema"]["properties"]["status"]["enum"]
            .as_array()
            .ok_or("enum not an array")?;
        assert!(enum_vals.contains(&json!("healthy")));
        assert!(enum_vals.contains(&json!("degraded")));
        assert!(enum_vals.contains(&json!("unhealthy")));
        Ok(())
    }

    // ========================================================================
    // generate_spec: Descriptions Are Non-Empty
    // ========================================================================

    #[test]
    fn test_all_operations_have_summaries() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let paths = spec["paths"].as_object().ok_or("paths not an object")?;
        for (path, methods) in paths {
            if let Some(obj) = methods.as_object() {
                for (method, details) in obj {
                    let summary = details["summary"]
                        .as_str()
                        .ok_or(format!("No summary for {method} {path}"))?;
                    assert!(!summary.is_empty(), "Empty summary for {method} {path}");
                }
            }
        }
        Ok(())
    }

    // ========================================================================
    // generate_spec: Challenge Path Description Content
    // ========================================================================

    #[test]
    fn test_challenge_path_description_mentions_pkce() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let desc = spec["paths"]["/v1/challenge"]["post"]["description"]
            .as_str()
            .ok_or("description not a string")?;
        assert!(desc.contains("PKCE"));
        Ok(())
    }

    #[test]
    fn test_redeem_path_description_mentions_code_verifier(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let desc = spec["paths"]["/v1/challenge/{session_id}/redeem"]["post"]["description"]
            .as_str()
            .ok_or("description not a string")?;
        assert!(desc.contains("code_verifier"));
        Ok(())
    }

    #[test]
    fn test_verify_path_description_mentions_zk() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let desc = spec["paths"]["/v1/verify"]["post"]["description"]
            .as_str()
            .ok_or("description not a string")?;
        assert!(desc.contains("zero-knowledge"));
        Ok(())
    }

    // ========================================================================
    // generate_spec: Spec Size Sanity
    // ========================================================================

    #[test]
    fn test_spec_serialised_size_reasonable() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let json_str = serde_json::to_string(&spec)?;
        // The spec should be non-trivial (> 5 KB) but not enormous (< 500 KB).
        assert!(
            json_str.len() > 5_000,
            "Spec too small: {} bytes",
            json_str.len()
        );
        assert!(
            json_str.len() < 500_000,
            "Spec too large: {} bytes",
            json_str.len()
        );
        Ok(())
    }
}
