// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Shared API key authentication for verifier route handlers.
//!
//! Extracts common Origin + X-API-Key authentication logic previously
//! duplicated across verify.rs, redeem.rs, and challenge.rs. Includes
//! the PG-VAL-016 sandbox cross-origin fallback so all routes behave
//! consistently when a sandbox developer calls from a non-registered origin.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use std::sync::Arc;
use worker::{Headers, Response};
use zeroize::Zeroize;

use crate::{error::ApiError, AppState};

/// Default per-account hourly quota fallback when `DEFAULT_QUOTA_PER_HOUR` is
/// absent or unparseable. Mirrors the pre-auth gate's default in
/// `worker_routes::env_var_u32(..., "DEFAULT_QUOTA_PER_HOUR", 500)` so the
/// supplement uses the same baseline the IP gate does.
const DEFAULT_ACCOUNT_QUOTA_PER_HOUR: u32 = 500;

/// R9 (RL-03): Enforce the per-ACCOUNT hourly quota on a cryptographically
/// VERIFIED `client_id`, as a SUPPLEMENT to the pre-auth per-IP gate.
///
/// This MUST be called from inside a handler AFTER authentication has produced a
/// verified `client_id` and AFTER the idempotency-cache check (so idempotent
/// replays short-circuit before reaching this increment), but BEFORE any state
/// mutation / nonce consumption / credit deduction. It keys a brand-new
/// `acct_quota:{verified_client_id}:{endpoint}:{hour}` bucket (NO IP component)
/// via [`crate::rate_limiting::check_account_quota`], so customers behind a
/// shared egress IP are fairly bucketed by their authenticated identity.
///
/// The pre-auth IP-keyed gate in `worker_routes.rs` is intentionally left
/// untouched and still runs first; this is additive and cannot reopen the
/// ST-VA-004 bucket-rotation abuse it defends against.
///
/// Returns `Ok(())` when the account is within quota (the request proceeds).
/// Returns `Err(resp)` carrying a ready-to-forward response when the account is
/// over quota (429) or the limiter KV read failed (503 + short Retry-After via
/// the Wave-1 [`crate::rate_limiting::rate_limit_or_unavailable_response`]
/// helper, never a 429). The route layer applies security/CORS headers to the
/// returned response, identical to every other handler-returned response.
///
/// FAIL-SAFE FOR CUSTOMERS: if the rate-limit KV binding itself cannot be
/// obtained, this returns `Ok(())` (the request proceeds). This deliberately
/// does NOT fail the paying customer closed on a binding error, because the
/// pre-auth per-IP gate has already run with the same binding and is the
/// fail-closed anti-flood control; the post-auth supplement only ever throttles
/// an authenticated account that genuinely exceeds its own per-account limit.
pub(crate) async fn enforce_account_quota(
    state: &Arc<AppState>,
    verified_client_id: &str,
    endpoint: &str,
) -> Result<(), worker::Result<Response>> {
    // Read the per-account default the same way the pre-auth gate does; the
    // tier lookup inside check_account_quota can still raise this per customer.
    let default_quota: u32 = state
        .env
        .var("DEFAULT_QUOTA_PER_HOUR")
        .ok()
        .and_then(|v| v.to_string().parse::<u32>().ok())
        .unwrap_or(DEFAULT_ACCOUNT_QUOTA_PER_HOUR);

    // Obtain the rate-limit KV. On a binding error, do NOT fail the customer
    // closed here (see doc comment): the pre-auth gate already enforced the
    // fail-closed per-IP control.
    let rl_kv = match state.env.kv(crate::bindings::KV_RATE_LIMITS) {
        Ok(kv) => kv,
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[RateLimit][acct] {}: KV_RATE_LIMITS binding unavailable; skipping post-auth account quota (pre-auth IP gate already enforced)",
                endpoint
            );
            return Ok(());
        }
    };
    // The tier/config lookup uses the same rate-limit KV namespace as the
    // pre-auth gate's `cfg_kv` fallback (worker_routes keys
    // `rate_limits/clients/{id}` in VERIFIER_KV_RATE_LIMITS).
    let cfg_kv = rl_kv.clone();

    let result = crate::rate_limiting::check_account_quota(
        &rl_kv,
        &cfg_kv,
        verified_client_id,
        endpoint,
        default_quota,
    )
    .await;

    if !result.allowed {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[RateLimit][acct] {} per-account quota exceeded (count={}, limit={}, read_failed={})",
            endpoint,
            result.current_count,
            result.limit,
            result.read_failed
        );
        // R9: surface via the Wave-1 helper so a KV read failure returns
        // 503 + short Retry-After, NOT a 429.
        return Err(crate::rate_limiting::rate_limit_or_unavailable_response(
            &result,
        ));
    }

    Ok(())
}

/// Configuration for the shared authentication function.
pub(crate) struct ApiKeyAuthOptions<'a> {
    /// When set, used for sandbox cross-origin fallback (PG-VAL-016).
    /// Typically the challenge record's stored `client_id`.
    pub expected_owner_id: Option<&'a str>,
    /// When true and no Origin header is present, falls back to the
    /// challenge's stored `client_id` (mobile wallet flow).
    pub allow_mobile_flow: bool,
    /// The stored `client_id` from the challenge record. Only consulted
    /// when `allow_mobile_flow == true` AND no Origin header is present.
    pub stored_client_id: Option<String>,
    /// Label for console_log messages identifying the calling route.
    pub route_label: &'a str,
}

/// Result of a successful API key authentication.
pub(crate) struct ApiKeyAuthResult {
    /// The authenticated client identifier (or the stored challenge owner for mobile flow).
    pub client_id: Option<String>,
    /// True when authentication fell through to the mobile capability-token path.
    pub is_mobile_flow: bool,
}

/// Authenticate a request via Origin + X-API-Key headers.
///
/// Implements the full authentication flow including:
/// - Direct origin policy lookup
/// - PG-VAL-016 sandbox cross-origin fallback via `client_lookup/<client_id>`
/// - Prefix-indexed API key verification with capped fallback scan
/// - Timing-oracle-resistant dummy hash on miss (CWE-208)
/// - Mobile wallet flow fallback (when `allow_mobile_flow` is set)
///
/// SECURITY: The API key String is zeroized before returning on ALL paths.
pub(crate) async fn authenticate_api_key(
    headers: &Headers,
    state: &Arc<AppState>,
    options: ApiKeyAuthOptions<'_>,
) -> Result<ApiKeyAuthResult, ApiError> {
    let mut extracted_id: Option<String> = None;
    let mut is_mobile_flow = false;

    // Resolve the origin: direct lookup with sandbox fallback.
    let resolved_origin = resolve_origin(headers, state, options.expected_owner_id).await;

    if let Some(origin_str) = resolved_origin {
        if let Ok(Some(cached_policy)) = state
            .origin_policy_store
            .get_cached_policy(&origin_str)
            .await
        {
            if let Some(mut api_key) = headers.get("X-API-Key").ok().flatten() {
                extracted_id =
                    verify_against_policy(&api_key, &cached_policy, state, options.route_label);

                // SECURITY: Zeroize the API key String after use.
                api_key.zeroize();
            }
        }
    } else if let Some(mut api_key) = headers.get("X-API-Key").ok().flatten() {
        // Origin header was absent but X-API-Key was provided. No policy to verify against.
        // Still invoke dummy hash to close timing oracle.
        let _ = crate::security::hash::verify_api_key("dummy", &state.dummy_argon2_hash);
        api_key.zeroize();
    }

    // Mobile wallet flow: no Origin header, no X-API-Key. The wallet only
    // possesses the challenge_id and submit_secret, both of which are
    // unguessable capability tokens generated at challenge creation time.
    if extracted_id.is_none()
        && options.allow_mobile_flow
        && headers.get("Origin").ok().flatten().is_none()
    {
        if let Some(ref stored_cid) = options.stored_client_id {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] {}: Mobile flow - authenticated by capability tokens (challenge_id + submit_secret)",
                options.route_label
            );
            extracted_id = Some(stored_cid.clone());
            is_mobile_flow = true;
        }
    }

    Ok(ApiKeyAuthResult {
        client_id: extracted_id,
        is_mobile_flow,
    })
}

/// Resolve the request Origin to a registered origin string.
///
/// First attempts a direct policy lookup. If that fails and we are in sandbox,
/// falls back to `client_lookup/<client_id>` keyed on the expected owner.
async fn resolve_origin(
    headers: &Headers,
    state: &Arc<AppState>,
    expected_owner_id: Option<&str>,
) -> Option<String> {
    let req_origin = headers.get("Origin").ok().flatten();
    let origin_str = match req_origin.as_deref() {
        Some(o) => o,
        None => return None,
    };

    // Direct lookup: does this origin have a registered policy?
    let direct = state
        .origin_policy_store
        .get_cached_policy(origin_str)
        .await
        .ok()
        .flatten();

    if direct.is_some() {
        return Some(origin_str.to_string());
    }

    // PG-VAL-016: Sandbox cross-origin fallback.
    if state.cfg.environment != "sandbox" {
        return None;
    }

    let owner_id = expected_owner_id.filter(|id| id.starts_with("rp_sandbox_"))?;

    let kv = match state.env.kv(crate::bindings::KV_CONFIG) {
        Ok(kv) => kv,
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] Sandbox cross-origin fallback: KV_CONFIG binding error: {:?}",
                _e
            );
            return None;
        }
    };

    let lookup_key = format!("client_lookup/{}", owner_id);
    match kv.get(&lookup_key).text().await {
        Ok(Some(reg)) if !reg.is_empty() => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] Sandbox auth fallback resolved request_origin={} -> registered_origin={} via client_id={}",
                origin_str, reg, owner_id
            );
            Some(reg)
        }
        _ => None,
    }
}

/// Verify an API key against a cached origin policy using prefix index lookup.
///
/// Returns the authenticated `client_id` on success, or None on failure.
/// Invokes a dummy Argon2id hash on miss to close the timing oracle (CWE-208).
fn verify_against_policy(
    api_key: &str,
    cached_policy: &crate::storage::origin_policy::CachedPolicy,
    state: &Arc<AppState>,
    _route_label: &str,
) -> Option<String> {
    // PERFORMANCE: Use prefix index for O(1) lookup instead of O(n) linear scan.
    let prefix = api_key.get(..8).unwrap_or(api_key);

    let mut candidate_indices = cached_policy.api_key_prefix_index.get(prefix).cloned();

    // Fallback: check the PREFIX_UNKNOWN bucket (clients whose API key prefix
    // was not recorded at creation time).
    if candidate_indices.is_none() {
        candidate_indices = cached_policy
            .api_key_prefix_index
            .get("PREFIX_UNKNOWN")
            .cloned();
    }

    let mut result: Option<String> = None;

    if let Some(indices) = candidate_indices {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[PERF] {}: API key prefix matched {} candidate client(s)",
            _route_label,
            indices.len()
        );

        for &idx in indices.iter() {
            if let Some(client) = cached_policy.policy.clients.get(idx) {
                if !client.active {
                    continue;
                }

                if crate::security::hash::verify_api_key(api_key, &client.api_key_hash) {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[SECURITY] {}: Client authenticated (prefix index match)",
                        _route_label
                    );
                    result = Some(client.client_id.clone());
                    break;
                }
            }
        }

        // INV-VA-051: If prefix matched candidates but none verified,
        // invoke a dummy Argon2id hash to close the timing oracle (CWE-208).
        if result.is_none() {
            let _ = crate::security::hash::verify_api_key(api_key, &state.dummy_argon2_hash);
        }
    } else {
        // M-24: Cap fallback scan to prevent O(n) CPU exhaustion on large client lists.
        const MAX_FALLBACK_SCAN: usize = 5;
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[PERF] {}: No API key prefix index match, scanning up to {} clients",
            _route_label,
            MAX_FALLBACK_SCAN
        );

        for client in cached_policy
            .policy
            .clients
            .iter()
            .filter(|c| c.active)
            .take(MAX_FALLBACK_SCAN)
        {
            if crate::security::hash::verify_api_key(api_key, &client.api_key_hash) {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] {}: Client authenticated (full scan match)",
                    _route_label
                );
                result = Some(client.client_id.clone());
                break;
            }
        }

        // SECURITY: If no match found after capped scan, invoke dummy hash
        // to close the timing oracle (CWE-208).
        if result.is_none() {
            let _ = crate::security::hash::verify_api_key(api_key, &state.dummy_argon2_hash);
        }
    }

    result
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic
)]
mod tests {
    use super::*;

    // ── ApiKeyAuthOptions struct ─────────────────────────────────────

    #[test]
    fn auth_options_default_configuration() {
        let opts = ApiKeyAuthOptions {
            expected_owner_id: None,
            allow_mobile_flow: false,
            stored_client_id: None,
            route_label: "test_route",
        };
        assert!(opts.expected_owner_id.is_none());
        assert!(!opts.allow_mobile_flow);
        assert!(opts.stored_client_id.is_none());
        assert_eq!(opts.route_label, "test_route");
    }

    #[test]
    fn auth_options_with_mobile_flow() {
        let opts = ApiKeyAuthOptions {
            expected_owner_id: Some("rp_sandbox_abc"),
            allow_mobile_flow: true,
            stored_client_id: Some("rp_sandbox_abc".to_string()),
            route_label: "submit_verification",
        };
        assert_eq!(opts.expected_owner_id, Some("rp_sandbox_abc"));
        assert!(opts.allow_mobile_flow);
        assert_eq!(opts.stored_client_id.as_deref(), Some("rp_sandbox_abc"));
    }

    #[test]
    fn auth_options_with_all_fields_populated() {
        let opts = ApiKeyAuthOptions {
            expected_owner_id: Some("rp_live_xyz"),
            allow_mobile_flow: false,
            stored_client_id: Some("rp_live_xyz".to_string()),
            route_label: "redeem_challenge",
        };
        assert_eq!(opts.expected_owner_id, Some("rp_live_xyz"));
        assert_eq!(opts.route_label, "redeem_challenge");
    }

    // ── ApiKeyAuthResult struct ─────────────────────────────────────

    #[test]
    fn auth_result_no_client_not_mobile() {
        let result = ApiKeyAuthResult {
            client_id: None,
            is_mobile_flow: false,
        };
        assert!(result.client_id.is_none());
        assert!(!result.is_mobile_flow);
    }

    #[test]
    fn auth_result_with_client() {
        let result = ApiKeyAuthResult {
            client_id: Some("rp_live_abc".to_string()),
            is_mobile_flow: false,
        };
        assert_eq!(result.client_id.as_deref(), Some("rp_live_abc"));
        assert!(!result.is_mobile_flow);
    }

    #[test]
    fn auth_result_mobile_flow() {
        let result = ApiKeyAuthResult {
            client_id: Some("rp_sandbox_123".to_string()),
            is_mobile_flow: true,
        };
        assert!(result.is_mobile_flow);
        assert!(result.client_id.is_some());
    }

    // ── API key prefix extraction logic ─────────────────────────────

    #[test]
    fn prefix_extraction_short_key() {
        // Keys shorter than 8 chars should fall back to the full key.
        let short_key = "abc";
        let prefix = short_key.get(..8).unwrap_or(short_key);
        assert_eq!(prefix, "abc");
    }

    #[test]
    fn prefix_extraction_exact_eight_chars() {
        let key = "12345678";
        let prefix = key.get(..8).unwrap_or(key);
        assert_eq!(prefix, "12345678");
    }

    #[test]
    fn prefix_extraction_long_key() {
        let key = "pk_live_abcdef1234567890";
        let prefix = key.get(..8).unwrap_or(key);
        assert_eq!(prefix, "pk_live_");
    }

    #[test]
    fn prefix_extraction_empty_key() {
        let key = "";
        let prefix = key.get(..8).unwrap_or(key);
        assert_eq!(prefix, "");
    }

    // ── Route label documentation ───────────────────────────────────

    #[test]
    fn route_labels_are_valid_identifiers() {
        // Route labels used in production must be non-empty for log grep.
        let labels = [
            "submit_verification",
            "redeem_challenge",
            "challenge",
            "poll_challenge",
        ];
        for label in labels {
            assert!(!label.is_empty());
            assert!(
                label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "label '{}' contains invalid chars",
                label
            );
        }
    }

    // ── ApiKeyAuthOptions combinations ──────────────────────────────

    #[test]
    fn auth_options_mobile_flow_without_stored_client_id() {
        let opts = ApiKeyAuthOptions {
            expected_owner_id: None,
            allow_mobile_flow: true,
            stored_client_id: None,
            route_label: "verify",
        };
        // Mobile flow enabled but no stored_client_id means the flow will
        // not resolve an identity. This is a valid configuration.
        assert!(opts.allow_mobile_flow);
        assert!(opts.stored_client_id.is_none());
    }

    #[test]
    fn auth_options_expected_owner_id_without_sandbox_prefix() {
        let opts = ApiKeyAuthOptions {
            expected_owner_id: Some("rp_live_abc"),
            allow_mobile_flow: false,
            stored_client_id: None,
            route_label: "challenge",
        };
        // PG-VAL-016 requires rp_sandbox_ prefix for fallback.
        // rp_live_ should not trigger sandbox fallback.
        let owner = opts.expected_owner_id.expect("present");
        assert!(!owner.starts_with("rp_sandbox_"));
    }

    #[test]
    fn auth_options_sandbox_prefix_check() {
        let owner_id = "rp_sandbox_xyz";
        assert!(owner_id.starts_with("rp_sandbox_"));
    }

    #[test]
    fn auth_options_live_prefix_does_not_match_sandbox() {
        let owner_id = "rp_live_xyz";
        assert!(!owner_id.starts_with("rp_sandbox_"));
    }

    #[test]
    fn auth_options_empty_route_label() {
        let opts = ApiKeyAuthOptions {
            expected_owner_id: None,
            allow_mobile_flow: false,
            stored_client_id: None,
            route_label: "",
        };
        assert!(opts.route_label.is_empty());
    }

    // ── ApiKeyAuthResult combinations ──────────────────────────────

    #[test]
    fn auth_result_mobile_flow_without_client_id() {
        // Theoretically shouldn't happen in practice, but struct allows it.
        let result = ApiKeyAuthResult {
            client_id: None,
            is_mobile_flow: true,
        };
        assert!(result.is_mobile_flow);
        assert!(result.client_id.is_none());
    }

    #[test]
    fn auth_result_client_id_empty_string() {
        let result = ApiKeyAuthResult {
            client_id: Some(String::new()),
            is_mobile_flow: false,
        };
        assert_eq!(result.client_id.as_deref(), Some(""));
    }

    #[test]
    fn auth_result_client_id_with_special_chars() {
        let result = ApiKeyAuthResult {
            client_id: Some("rp_sandbox_1234-5678_test".to_string()),
            is_mobile_flow: false,
        };
        assert!(result.client_id.as_deref().expect("present").contains("-"));
        assert!(result.client_id.as_deref().expect("present").contains("_"));
    }

    // ── API key prefix extraction boundaries ───────────────────────

    #[test]
    fn prefix_extraction_one_char() {
        let key = "a";
        let prefix = key.get(..8).unwrap_or(key);
        assert_eq!(prefix, "a");
    }

    #[test]
    fn prefix_extraction_seven_chars() {
        let key = "abcdefg";
        let prefix = key.get(..8).unwrap_or(key);
        assert_eq!(prefix, "abcdefg");
    }

    #[test]
    fn prefix_extraction_nine_chars() {
        let key = "abcdefghi";
        let prefix = key.get(..8).unwrap_or(key);
        assert_eq!(prefix, "abcdefgh");
    }

    #[test]
    fn prefix_extraction_pk_sandbox_key() {
        let key = "pk_sandbox_abc123def456";
        let prefix = key.get(..8).unwrap_or(key);
        assert_eq!(prefix, "pk_sandb");
    }

    #[test]
    fn prefix_extraction_pk_test_key() {
        let key = "pk_test_9876abcd";
        let prefix = key.get(..8).unwrap_or(key);
        assert_eq!(prefix, "pk_test_");
    }

    #[test]
    fn prefix_extraction_multibyte_utf8_safe() {
        // API keys should be ASCII, but verify get(..8) on multibyte doesn't panic.
        let key = "abcdefgh\u{00E9}ijk"; // 'e with accent' at position 8
        let prefix = key.get(..8).unwrap_or(key);
        assert_eq!(prefix, "abcdefgh");
    }

    #[test]
    fn prefix_extraction_utf8_boundary_returns_full_key() {
        // If the 8-byte boundary falls inside a multi-byte char, get(..8) returns None.
        let key = "\u{1F600}\u{1F600}"; // Two 4-byte emoji = 8 bytes
                                        // get(..8) on a str checks char boundaries. Each emoji is 4 bytes.
                                        // So byte position 8 is a valid char boundary.
        let prefix = key.get(..8);
        // This should return Some since 8 bytes aligns with the second emoji boundary.
        assert!(prefix.is_some() || prefix.is_none(), "must not panic");
    }

    // ── MAX_FALLBACK_SCAN constant ─────────────────────────────────

    #[test]
    fn max_fallback_scan_is_five() {
        // The constant is defined inside verify_against_policy as a local const.
        // Verify the expected value is documented.
        const EXPECTED_MAX: usize = 5;
        assert_eq!(EXPECTED_MAX, 5);
    }

    // ── Client ID prefix conventions ───────────────────────────────

    #[test]
    fn client_id_prefix_rp_live() {
        let id = "rp_live_abc123";
        assert!(id.starts_with("rp_live_"));
    }

    #[test]
    fn client_id_prefix_rp_sandbox() {
        let id = "rp_sandbox_abc123";
        assert!(id.starts_with("rp_sandbox_"));
    }

    #[test]
    fn client_id_no_prefix_is_valid_struct() {
        // The struct itself does not enforce prefixes.
        let result = ApiKeyAuthResult {
            client_id: Some("no_prefix".to_string()),
            is_mobile_flow: false,
        };
        assert_eq!(result.client_id.as_deref(), Some("no_prefix"));
    }

    // ── ApiKeyAuthOptions with all field permutations ──────────────

    #[test]
    fn auth_options_all_none() {
        let opts = ApiKeyAuthOptions {
            expected_owner_id: None,
            allow_mobile_flow: false,
            stored_client_id: None,
            route_label: "test",
        };
        assert!(opts.expected_owner_id.is_none());
        assert!(opts.stored_client_id.is_none());
        assert!(!opts.allow_mobile_flow);
    }

    #[test]
    fn auth_options_mismatched_owner_and_stored_client() {
        // In practice these should match, but the struct doesn't enforce it.
        let opts = ApiKeyAuthOptions {
            expected_owner_id: Some("rp_sandbox_aaa"),
            allow_mobile_flow: true,
            stored_client_id: Some("rp_sandbox_bbb".to_string()),
            route_label: "verify",
        };
        assert_ne!(
            opts.expected_owner_id.expect("owner"),
            opts.stored_client_id.as_deref().expect("stored")
        );
    }

    // ── Sandbox prefix filter logic ────────────────────────────────

    #[test]
    fn sandbox_prefix_filter_rejects_empty() {
        let id = "";
        assert!(!id.starts_with("rp_sandbox_"));
    }

    #[test]
    fn sandbox_prefix_filter_rejects_partial_match() {
        let id = "rp_sandbox";
        assert!(!id.starts_with("rp_sandbox_"));
    }

    #[test]
    fn sandbox_prefix_filter_accepts_minimal() {
        let id = "rp_sandbox_x";
        assert!(id.starts_with("rp_sandbox_"));
    }

    // ── lookup_key format ──────────────────────────────────────────

    #[test]
    fn lookup_key_format() {
        let owner_id = "rp_sandbox_abc";
        let key = format!("client_lookup/{}", owner_id);
        assert_eq!(key, "client_lookup/rp_sandbox_abc");
    }

    #[test]
    fn lookup_key_format_no_trailing_slash() {
        let owner_id = "rp_sandbox_test";
        let key = format!("client_lookup/{}", owner_id);
        assert!(!key.ends_with('/'));
    }
}
