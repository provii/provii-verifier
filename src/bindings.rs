// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Centralised binding names for KV namespaces and Durable Objects.
//!
//! These constants map to the binding names declared in `wrangler.toml`. Actual
//! namespace IDs differ per environment. Every binding carries the `VERIFIER_`
//! prefix so that service-specific isolation is enforced and cross-service data
//! access is prevented.

// --------------------------------------------------------------------------
// KV Namespaces
// --------------------------------------------------------------------------

/// KV namespace for configuration data (JWKS, CRL, policies, etc.).
pub const KV_CONFIG: &str = "VERIFIER_KV_CONFIG";

/// KV namespace for credential banlist (revoked credentials).
pub const KV_BANLIST: &str = "VERIFIER_KV_BANLIST";

/// KV namespace for distributed rate limiting.
pub const KV_RATE_LIMITS: &str = "VERIFIER_KV_RATE_LIMITS";

/// KV namespace for issuer registry (approved issuers, revocation status).
pub const KV_ISSUER_REGISTRY: &str = "VERIFIER_KV_ISSUER_REGISTRY";

// --------------------------------------------------------------------------
// Durable Objects
// --------------------------------------------------------------------------

/// Durable Object for challenge storage and validation.
pub const DO_CHALLENGE: &str = "VERIFIER_DO_CHALLENGE";

/// Durable Object for nonce storage and replay prevention.
pub const DO_NONCE: &str = "VERIFIER_DO_NONCE";

/// Durable Object for idempotency key storage (ASVS V11, OWASP API4:2023).
pub const DO_IDEMPOTENCY: &str = "VERIFIER_DO_IDEMPOTENCY";
