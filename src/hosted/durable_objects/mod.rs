// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Hosted Durable Objects implementations for the verifier API
//!
//! Contains Durable Object implementations with sharding support for
//! hosted verification sessions. Hosted session payloads are stored
//! encrypted in the HOSTED_SESSIONS KV namespace; DOs are used for
//! replay protection (nonces), idempotency, and WebSocket-based change
//! notifications.

pub mod challenge_notify_do;
pub mod hosted_idempotency_do;
pub mod hosted_nonce_do;
pub mod sharding;

// Export the main DO structs and key types
pub use challenge_notify_do::ChallengeNotifyDO;
pub use hosted_idempotency_do::HostedIdempotencyDO;
pub use hosted_nonce_do::{HostedNonceDO, HostedNonceDOAuditEvent};
pub use sharding::*;
