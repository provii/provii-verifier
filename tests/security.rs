// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust
//! Security test module
//!
//! Comprehensive security tests for the provii-verifier, including SSRF
//! protection, input validation, and other security controls.
#![forbid(unsafe_code)]

#[path = "security/ssrf_protection_test.rs"]
mod ssrf_protection_test;

#[path = "security/prefix_rejection_test.rs"]
mod prefix_rejection_test;

#[path = "security/canonical_message_test.rs"]
mod canonical_message_test;

#[path = "security/docs_hmac_test.rs"]
mod docs_hmac_test;

#[path = "security/hmac_secret_encoding_test.rs"]
mod hmac_secret_encoding_test;

#[path = "security/internal_traffic_guard_test.rs"]
mod internal_traffic_guard_test;
