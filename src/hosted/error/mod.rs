// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Error Handling Module for Hosted Verification Flows
//!
//! SECURITY: This module provides error sanitisation and standardised error
//! responses to prevent information disclosure vulnerabilities. In production,
//! error messages are stripped of internal details (stack traces, file paths,
//! SQL queries) while full details are logged internally. Error verbosity is
//! environment-aware.

pub mod codes;
pub mod sanitizer;

pub use codes::{map_error_to_code, ErrorCode};
pub use sanitizer::{sanitize_error, ErrorSanitizer};
