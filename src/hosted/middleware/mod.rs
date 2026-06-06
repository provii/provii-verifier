// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Middleware modules for hosted verification flow HTTP request/response processing.
//!
//! Provides request body size limits, security headers, Content-Type
//! validation, correlation IDs for distributed tracing, Sec-Fetch metadata
//! validation (CSRF and clickjacking prevention), and re-authentication
//! enforcement for sensitive operations.

pub mod body_size_limit;
pub mod request_validation;
pub mod sec_fetch;
pub mod security_headers;

// Re-export commonly used types
pub use body_size_limit::BodySizeLimitConfig;
pub use request_validation::validate_content_type;
pub use sec_fetch::{
    validate_sec_fetch_lenient, SecFetchConfig, SecFetchPolicy, SecFetchValidator,
};
pub use security_headers::{
    add_cache_control_headers, add_security_headers, CacheControlPolicy, SecurityHeadersConfig,
    SecurityProfile,
};
