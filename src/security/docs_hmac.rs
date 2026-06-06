// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Docs-gateway HMAC verification (task W6-NT3).
//!
//! The docs-sandbox gateway (see `provii-demos/demo-web-provii-agegate/src/docs/
//! credentials.ts`) signs every outbound request body with its shared
//! `SANDBOX_API_KEY` and sends the tag in the `X-Docs-Hmac` header. This
//! module recomputes the same tag and constant-time compares it, giving
//! the upstream route an independent authentication layer that is neither
//! the existing IP rate limit nor the KV feature gate nor the service
//! binding itself. Defence in depth.
//!
//! # Why this, not just the service binding?
//!
//! A service binding forwards the request from one worker to another inside
//! the Cloudflare runtime. It is strong against public-internet attackers
//! but does not protect against:
//!
//!   - A compromised gateway worker (bug, supply-chain, or misconfig).
//!   - A future refactor that accidentally exposes the upstream route on a
//!     public hostname.
//!   - A sandbox credential minted by a rogue caller replayed against the
//!     upstream before the gateway's own rate limit trips.
//!
//! The HMAC is verified against a secret that only the legitimate gateway
//! and upstream hold. The tag is computed over the full request body, so
//! an attacker who learns the secret still cannot tamper with bodies in
//! transit without invalidating the tag.
//!
//! # Contract
//!
//! - Header: `X-Docs-Hmac`, hex-encoded HMAC-SHA-256 of the request body.
//! - Key: UTF-8 bytes of `SANDBOX_API_KEY` (provii-verifier) or
//!   `SANDBOX_ISSUER_API_KEY` (provii-issuer). The gateway-side signer lives
//!   in `credentials.ts::signUpstreamBody` and uses `TextEncoder` over the
//!   same key string.
//! - Comparison: `hmac::Mac::verify_slice`, which performs a constant-time
//!   check internally. No hand-rolled byte comparison.
//! - Rejection status: 401, body `{"error":"docs_hmac_invalid","code":"docs_hmac_invalid"}`.
//!   The caller-visible string is deliberately stable so the integration test
//!   on the gateway side can assert against it.
//!
//! # Scope
//!
//! The module is environment-agnostic. Route handlers gate the check on
//! `cfg.environment == "sandbox"` and on the presence of a cached secret,
//! so the verification runs on sandbox builds only. Production callers never
//! reach these routes in the first place (the provii-verifier route is gated on
//! `state.cfg.environment == "sandbox"`, and the provii-issuer route is gated
//! behind the `sandbox_only_register_test_issuer_client` Cargo feature plus
//! the `SANDBOX_DOCS_ISSUERS` KV binding).

#![forbid(unsafe_code)]

// Re-export from the pure-logic crate so existing call sites compile unchanged.
pub use provii_verifier_logic::docs_hmac::DocsHmacCheck;
pub use provii_verifier_logic::docs_hmac::DOCS_HMAC_HEADER;
pub use provii_verifier_logic::docs_hmac::DOCS_HMAC_REJECTION_CODE;

// Delegate to the pure-logic crate. These thin wrappers preserve the
// existing public API surface and call sites unchanged.
pub use provii_verifier_logic::docs_hmac::verify_docs_hmac;
pub use provii_verifier_logic::docs_hmac::verify_or_reject_hmac_key;

// Full test suite lives in `crates/verifier-logic/src/docs_hmac.rs`.
// These delegation sanity checks verify the re-exports compile and
// produce correct results through the wrapper layer.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_constants_stable() {
        assert_eq!(DOCS_HMAC_HEADER, "X-Docs-Hmac");
        assert_eq!(DOCS_HMAC_REJECTION_CODE, "docs_hmac_invalid");
    }

    #[test]
    fn delegation_verify_rejects_missing() {
        assert_eq!(
            verify_docs_hmac(None, b"{}", b"key"),
            DocsHmacCheck::MissingHeader
        );
    }

    #[test]
    fn delegation_verify_or_reject_key_rejects_none() {
        assert_eq!(
            verify_or_reject_hmac_key(None).unwrap_err(),
            DocsHmacCheck::MissingHeader
        );
    }
}
