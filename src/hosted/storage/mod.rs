// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Storage layer for the hosted verification subsystem.
//!
//! # Session storage architecture
//!
//! KV (`HOSTED_SESSIONS`) provides fast encrypted session storage with TTL-based
//! expiration. Durable Objects provide atomic nonce replay prevention and
//! idempotency guarantees.
#![forbid(unsafe_code)]

pub mod kv;

pub use kv::*;
