// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Hosted verification flow modules.
//!
//! Ported from provii-verifier for the provii-verifier to provii-verifier merger.
//! Provides browser-friendly age verification with public key auth, session
//! management, cookies, and WebSocket push notifications.

// Endpoint handlers
pub mod endpoints;

// Storage layer
pub mod durable_objects;
pub mod encryption;
pub mod storage;

// Types and errors
pub mod error;
pub mod keys;
pub mod types;

// Security and middleware
pub mod cookie;
pub mod cors;
pub mod middleware;
pub mod pkce;
pub mod rate_limiting;
pub mod session_binding;
