// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Security module for provii-verifier.
//!
//! Provides headers, input validation, audit logging, rate limiting,
//! idempotency, envelope encryption, and log sanitisation.
#![forbid(unsafe_code)]

pub mod audit;
pub mod auth;
pub mod docs_hmac;
pub mod envelope_encryption;
pub mod fetch_metadata;
pub mod hash;
pub mod headers;
pub mod idempotency;
pub mod log_sanitizer;
pub mod prefix_rejection;
pub mod secret_expiry;
pub mod secret_fingerprint;
pub mod secret_versions;
pub mod sri;
pub mod status_auth;
pub mod status_token_cache;
pub mod validation;

pub use audit::{AuditEventData, AuditLogger, DOResponse};
pub use auth::ClientAuthenticator;
pub use docs_hmac::{
    verify_docs_hmac, verify_or_reject_hmac_key, DocsHmacCheck, DOCS_HMAC_HEADER,
    DOCS_HMAC_REJECTION_CODE,
};
pub use envelope_encryption::{
    decrypt_hmac_secret, encrypt_hmac_secret, generate_random_iv, generate_random_key,
    EncryptedSecret, ENCRYPTION_VERSION_V1,
};
pub use fetch_metadata::{
    validate_fetch_metadata, validate_fetch_metadata_csp, validate_fetch_metadata_strict,
    validate_sec_fetch_dest, validate_sec_fetch_mode, validate_sec_fetch_site,
};
pub use hash::{hash_api_key, verify_api_key};
pub use headers::{
    add_internal_security_headers, add_security_headers, generate_csp_nonce,
    internal_security_headers, SecurityHeaders,
};
pub use idempotency::{
    check_idempotency, compute_request_fingerprint, extract_idempotency_key,
    store_idempotency_response, DEFAULT_IDEMPOTENCY_TTL_SECS,
};
pub use log_sanitizer::{hash_ip, redact_challenge_id, redact_session_id};
pub use prefix_rejection::{check_request as check_prefix_rejection, PrefixCheck};
pub use secret_expiry::{check_secret_expiry, log_expiry_warnings};
pub use secret_versions::{RotationSlot, SecretVersionLine};
pub use sri::{generate_swagger_ui_html, link_stylesheet_with_sri, script_tag_with_sri};
pub use status_auth::{authenticate_status_endpoint, StatusAuthOutcome, StatusAuthSlot};
pub use validation::{InputValidator, ValidationRules};
