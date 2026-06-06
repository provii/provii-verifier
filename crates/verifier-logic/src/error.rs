// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Minimal error type for the logic crate.
//!
//! The root crate's `error.rs` depends on `worker::Response` and cannot be
//! used in a native-only context. This enum covers only the failure modes
//! that the pure-logic functions can produce. The root crate implements
//! `From<LogicError> for ApiError` to bridge the two.

use std::fmt;

/// Errors produced by pure verification logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogicError {
    /// HMAC key was rejected (should never happen for HMAC-SHA-256).
    HmacKeyRejected,

    /// A supplied value could not be decoded from hex.
    InvalidHex,

    /// HMAC tag verification failed (constant-time mismatch).
    HmacMismatch,

    /// An HMAC tag or header was missing where one was required.
    MissingInput,

    /// The supplied HMAC header value was malformed (not valid hex).
    MalformedInput,

    /// Session binding mismatch in strict mode.
    SessionBindingMismatch,
}

impl fmt::Display for LogicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogicError::HmacKeyRejected => write!(f, "HMAC key rejected"),
            LogicError::InvalidHex => write!(f, "invalid hex encoding"),
            LogicError::HmacMismatch => write!(f, "HMAC tag mismatch"),
            LogicError::MissingInput => write!(f, "required input missing"),
            LogicError::MalformedInput => write!(f, "malformed input"),
            LogicError::SessionBindingMismatch => write!(f, "session binding mismatch"),
        }
    }
}

impl std::error::Error for LogicError {}
