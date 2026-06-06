// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Storage abstractions for challenges, nonces, and bans.
//!
//! Each trait defines the minimal surface that route handlers depend on.
//! Concrete implementations live in sibling modules (`kv`, `ban_store`).
#![forbid(unsafe_code)]

use crate::cache::CachedChallenge;
use crate::error::ApiResult;
use async_trait::async_trait;
use std::time::Duration;
use uuid::Uuid;

/// Persistent store for age-verification challenges.
///
/// Implementations must be safe to share across concurrent requests within a
/// single Cloudflare Worker isolate (`Send + Sync`). The default `put` and
/// `cleanup_expired` methods delegate to `insert` and return a no-op count
/// respectively; backends may override them for efficiency.
#[async_trait(?Send)]
pub trait ChallengeStore: Send + Sync {
    /// Write a new challenge, replacing any existing entry with the same `id`.
    async fn insert(&self, id: Uuid, challenge: CachedChallenge) -> ApiResult<()>;

    /// Retrieve a challenge by its UUID, returning `None` if absent or expired.
    async fn get(&self, id: &Uuid) -> ApiResult<Option<CachedChallenge>>;

    /// Delete a challenge and return the previously stored value (if any).
    async fn remove(&self, id: &Uuid) -> ApiResult<Option<CachedChallenge>>;

    /// Overwrite an existing challenge (semantically identical to `insert`).
    async fn update(&self, id: Uuid, challenge: CachedChallenge) -> ApiResult<()>;

    /// Convenience alias for `insert` that borrows rather than consumes.
    async fn put(&self, id: &Uuid, challenge: &CachedChallenge) -> ApiResult<()> {
        self.insert(*id, challenge.clone()).await
    }

    /// Remove expired entries and return the number deleted. Default is a no-op.
    async fn cleanup_expired(&self) -> ApiResult<usize> {
        Ok(0)
    }
}

/// Replay-resistant nonce store for HMAC authentication.
///
/// `check_and_set` atomically checks whether a nonce tag has been seen within
/// the given TTL window. Returns `true` if the nonce is fresh (first use) and
/// `false` if it has already been consumed.
#[async_trait(?Send)]
pub trait NonceStore: Send + Sync {
    /// Atomically test-and-set a nonce tag. Returns `true` on first use.
    async fn check_and_set(&self, nonce_tag: &str, ttl: Duration) -> ApiResult<bool>;

    /// Remove expired entries and return the number deleted. Default is a no-op.
    async fn cleanup_expired(&self) -> ApiResult<usize> {
        Ok(0)
    }
}

/// Read-only view of the nullifier ban list.
///
/// Banned nullifiers prevent a revoked credential from passing verification.
#[async_trait(?Send)]
pub trait BanStore: Send + Sync {
    /// Returns `true` if the 32-byte nullifier is on the ban list.
    async fn is_banned(&self, nullifier: &[u8; 32]) -> ApiResult<bool>;
}
