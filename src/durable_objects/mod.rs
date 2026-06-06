// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Durable Object modules for the verifier API.
//!
//! Each Durable Object encapsulates a distinct coordination concern that
//! cannot be safely handled by stateless Workers alone:
//!
//! - [`ChallengeDO`]: Persistent challenge lifecycle storage and state machine.
//!   Per-challenge single-writer serialisation eliminates the need for a
//!   separate distributed lock.
//! - [`IdempotencyDO`]: Tracks idempotency keys with cached responses to
//!   prevent duplicate operations under retry storms.
//! - [`NonceDO`]: Single-use nonce tracking for replay attack prevention.

pub mod challenge_do;
pub mod challenge_lock_stub;
pub mod idempotency_do;
pub mod nonce_do;

pub use challenge_do::ChallengeDO;
pub use challenge_lock_stub::ChallengeLock;
pub use idempotency_do::IdempotencyDO;
pub use nonce_do::NonceDO;
