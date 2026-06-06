// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Storage backends for challenges, nonces, bans, idempotency, and origin policy.
//!
//! All persistent state lives in Cloudflare KV or Durable Objects. This module
//! re-exports the concrete stores and the abstract traits they implement so that
//! route handlers can depend on trait objects rather than specific backends.
#![forbid(unsafe_code)]

/// KV-backed ban list storage.
pub mod ban_store;
/// Durable Object-backed challenge storage.
pub mod do_challenge_store;
/// Durable Object-backed nonce store with atomic check-and-set.
pub mod durable_object_store;
/// Durable Object idempotency key storage.
pub mod idempotency_store;
/// Issuer registry cache with stale-while-revalidate resilience.
pub mod jwks;
/// Origin policy definitions and KV-backed lookup with in-memory cache.
pub mod origin_policy;
/// Abstract storage traits for challenges, nonces, and bans.
pub mod traits;

pub use ban_store::KvBanStore;
pub use do_challenge_store::DurableObjectChallengeStore;
pub use durable_object_store::DurableObjectNonceStore;
pub use idempotency_store::DurableObjectIdempotencyStore;
pub use origin_policy::{OriginPolicy, OriginPolicyStore, PolicyLookupResult};
pub use traits::{BanStore, ChallengeStore, NonceStore};

use std::sync::{Arc, OnceLock};

use crate::security::AuditLogger;

/// Shared, late-bound slot for the worker-level [`AuditLogger`].
///
/// Storage backends are constructed before the audit logger because the
/// logger requires the IP hash salt fetched asynchronously from Secrets
/// Store. To allow the storage layer to dispatch audit events emitted by
/// Durable Objects (AL-008) we share an `Arc<OnceLock<Arc<AuditLogger>>>`
/// between the storage layer and `init_app_state_internal`. Once the logger
/// is built it is `set()` exactly once and observed by every store.
pub type AuditLoggerSlot = Arc<OnceLock<Arc<AuditLogger>>>;
