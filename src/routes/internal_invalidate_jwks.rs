// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Push-invalidation endpoint for the issuer registry JWKS cache.
//!
//! Called by provii-management (via service binding) when an issuer is revoked.
//! Clears the in-memory cache and bumps the epoch counter so that any
//! in-flight background refresh does not overwrite the invalidation.
//!
//! Auth model: `reject_external_internal_traffic` guard (same as all
//! `/_internal/*` routes). Service-binding traffic from provii-management
//! does not carry `CF-Connecting-IP`, so the guard passes. External
//! requests are rejected with 401.
#![forbid(unsafe_code)]

use std::sync::Arc;
use worker::Response;

use crate::storage::jwks::JwksCache;

/// Handler for `POST /_internal/invalidate-jwks`.
///
/// Clears the issuer registry cache and bumps the invalidation epoch.
/// Returns 200 with a JSON body confirming the invalidation and the
/// new epoch value.
///
/// ADV-VA-11-002: This endpoint previously lacked bearer auth, relying solely
/// on `reject_external_internal_traffic`. Use [`handle_invalidate_jwks_authed`]
/// for routes that can supply AppState and request headers.
pub fn handle_invalidate_jwks(jwks_cache: &Arc<JwksCache>) -> Result<Response, worker::Error> {
    jwks_cache.invalidate();

    let epoch = jwks_cache.epoch();
    let body = serde_json::json!({
        "ok": true,
        "action": "jwks_cache_invalidated",
        "epoch": epoch,
    });

    Response::from_json(&body)
}

/// ADV-VA-11-002: Authenticated wrapper for `POST /_internal/invalidate-jwks`.
///
/// Validates a bearer token against the status-endpoint dual-slot auth scheme
/// before delegating to [`handle_invalidate_jwks`]. Returns 401 if the token
/// is missing or invalid.
///
/// Wired into the router at `worker_routes.rs` behind both
/// `reject_external_internal_traffic` and bearer auth.
pub async fn handle_invalidate_jwks_authed(
    jwks_cache: &Arc<JwksCache>,
    headers: &worker::Headers,
    state: &crate::AppState,
    env: &worker::Env,
    client_ip: &str,
) -> Result<Response, worker::Error> {
    // ADV-VA-11-002: Validate bearer auth matching the pattern used by
    // other /_internal/* endpoints (dual-slot accept via AppState tokens).
    match crate::security::authenticate_status_endpoint(
        env,
        headers,
        "invalidate_jwks",
        &state.audit_logger,
        client_ip,
        None,
        &state.ip_hash_salt,
    )
    .await
    {
        Ok(_outcome) => handle_invalidate_jwks(jwks_cache),
        Err(_) => {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "{{\"audit\":true,\"event\":\"invalidate_jwks_auth_failed\",\"severity\":\"warning\"}}"
            );
            let body = serde_json::json!({ "error": "Unauthorised" });
            Ok(Response::from_json(&body)?.with_status(401))
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn handler_module_compiles() {
        // Structural test: the module compiles and exports are accessible.
        // Full integration tests require the Workers runtime (KvStore).
    }
}
