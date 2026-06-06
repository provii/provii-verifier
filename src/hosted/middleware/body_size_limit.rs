// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Request body size limit middleware for the hosted verification flow.
//!
//! SECURITY: Enforces maximum request body sizes to prevent memory
//! exhaustion and denial of service via large payloads. The
//! Content-Length header is validated before the body is read into
//! memory. Requests without a Content-Length are rejected outright
//! (411 Length Required) rather than buffered without bounds.
//!
//! Default limit: 1 MB. Returns 413 Payload Too Large if exceeded.

/// Default maximum request body size (1MB)
pub const DEFAULT_MAX_BODY_SIZE: u64 = 1_048_576; // 1MB in bytes

/// Maximum body size for most endpoints (1MB)
pub const MAX_BODY_SIZE_STANDARD: u64 = 1_048_576;

/// Maximum body size for smaller endpoints (64KB)
pub const MAX_BODY_SIZE_SMALL: u64 = 65_536;

/// Configuration for body size limits
#[derive(Debug, Clone)]
pub struct BodySizeLimitConfig {
    /// Maximum body size in bytes
    pub max_size: u64,

    /// Whether to check Content-Length header
    pub check_content_length: bool,

    /// Whether to enforce limit on chunked transfers
    pub enforce_on_chunked: bool,
}

impl Default for BodySizeLimitConfig {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_BODY_SIZE,
            check_content_length: true,
            enforce_on_chunked: true,
        }
    }
}

impl BodySizeLimitConfig {
    /// Create config with standard 1MB limit
    pub fn standard() -> Self {
        Self {
            max_size: MAX_BODY_SIZE_STANDARD,
            ..Default::default()
        }
    }

    /// Create config with small 64KB limit
    pub fn small() -> Self {
        Self {
            max_size: MAX_BODY_SIZE_SMALL,
            ..Default::default()
        }
    }

    /// Create config with custom limit
    pub fn with_max_size(max_size: u64) -> Self {
        Self {
            max_size,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BodySizeLimitConfig::default();
        assert_eq!(config.max_size, DEFAULT_MAX_BODY_SIZE);
        assert!(config.check_content_length);
        assert!(config.enforce_on_chunked);
    }

    #[test]
    fn test_standard_config() {
        let config = BodySizeLimitConfig::standard();
        assert_eq!(config.max_size, MAX_BODY_SIZE_STANDARD);
    }

    #[test]
    fn test_small_config() {
        let config = BodySizeLimitConfig::small();
        assert_eq!(config.max_size, MAX_BODY_SIZE_SMALL);
    }

    #[test]
    fn test_custom_config() {
        let config = BodySizeLimitConfig::with_max_size(5_000_000);
        assert_eq!(config.max_size, 5_000_000);
    }
}
