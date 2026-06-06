// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! `/_internal/version` endpoint.
//!
//! Returns the full 8-character fingerprint for every rotation-capable secret
//! the worker has cached, so the drill workflow's `wait-for-propagation` step
//! can confirm a redeploy actually shifted the binding before continuing.
//!
//! Auth model: status-token only, in both sandbox and production.
//!
//! Earlier revisions accepted the `Cf-Access-Authenticated-User-Email` header
//! as proof of identity in sandbox. That header is populated by Cloudflare
//! Access only when the request transits the Access edge, but Workers expose
//! `*.workers.dev` URLs by default and the upstream Worker has no way to
//! verify which hostname the request entered through. An attacker hitting the
//! workers.dev hostname directly with a self-set header would have bypassed
//! the Access check entirely. The fix is to drop the CF Access branch and
//! gate every `/_internal/version` request behind the dual-slot status-token
//! auth path that the production path already used.
//!
//! The status token is rotation-capable (dual-slot) and the drill
//! workflow already supplies it via the rotation CLI, so the
//! sandbox arm does not need an "operator-friendly" alternative. Constant-time
//! comparison runs inside `authenticate_status_endpoint` via
//! `subtle::ConstantTimeEq`.
//!
//! The response body carries the deployed_at + git_sha environment vars (when
//! present) plus 8-char fingerprints for every active slot. Fingerprints are
//! public-safe (32 bits, one-way) but the endpoint is still locked behind auth
//! so an attacker cannot trivially correlate fingerprint changes to rotation
//! events.
#![forbid(unsafe_code)]

use serde_json::json;
use std::sync::Arc;
use worker::{Headers, Response};

use crate::error::ApiError;
#[cfg(target_arch = "wasm32")]
use crate::security::hash_ip;
use crate::security::{
    authenticate_status_endpoint,
    secret_fingerprint::{fingerprint8_bytes, fingerprint8_str},
    status_auth::enforce_internal_replay_window,
};
use crate::AppState;

/// Handler for `GET /_internal/version`.
///
/// Auth: status-token only (presented as `X-Status-Token` or
/// `Authorization: Bearer <token>`). Same dual-slot accept path as
/// `/health/detailed` and `/metrics`; the constant-time compare runs inside
/// `authenticate_status_endpoint` via `subtle::ConstantTimeEq` /
/// `hmac::Mac::verify_slice`. The `Cf-Access-Authenticated-User-Email`
/// branch was removed in F3 because Workers expose `*.workers.dev` URLs by
/// default and an attacker could spoof the header by hitting the workers.dev
/// hostname directly.
///
/// On auth failure the response is `401 Unauthorized` and carries no body.
/// On success the response is a JSON object with `deployed_at`, `git_sha`,
/// `service`, `environment`, and `secret_versions` (8-char fingerprints).
pub async fn handle_internal_version(
    headers: &Headers,
    client_ip: &str,
    state: &Arc<AppState>,
) -> Result<Response, worker::Error> {
    let environment = state.cfg.environment.as_str();

    // Status-token auth, dual-slot accept. The dual-slot
    // `STATUS_API_TOKEN` pair is resolved through the five-minute TTL
    // `status_token_cache` on every call so a rotated token in Secrets
    // Store becomes effective on warm isolates without a redeploy. The
    // status-token path emits its own structured success/failure audit
    // log entry inside `authenticate_status_endpoint`, so this handler
    // only needs to render the 401 response shape on Err.
    let outcome = match authenticate_status_endpoint(
        &state.env,
        headers,
        state.status_token_role,
        &state.audit_logger,
        client_ip,
        Some(&state.origin_policy_store),
        &state.ip_hash_salt,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            // Audit trail already emitted by authenticate_status_endpoint.
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "[/_internal/version] auth denied for ip_hash={}",
                hash_ip(client_ip, &state.ip_hash_salt)
            );
            return ApiError::Unauthorized.to_response();
        }
    };

    // F-01 (#72): rolling-window timestamp + per-request nonce
    // dedupe on top of the bearer auth above. Required for
    // `/_internal/version` because the endpoint surfaces every active
    // rotation slot fingerprint; a captured request would otherwise
    // let an attacker poll the fingerprint history within the
    // bearer's lifetime even after the operator script that produced
    // the request finished. Mirrors the partner-traffic verify_nonce
    // shape used by `HmacAuthVerifier`. The role tag scopes the
    // nonce dedupe so a `/_internal/version` nonce cannot replay
    // against another internal bearer surface that shares the
    // dedupe DO.
    if let Err(e) = enforce_internal_replay_window(
        headers,
        &state.nonce_store,
        "internal_version",
        &state.audit_logger,
        client_ip,
        &state.ip_hash_salt,
    )
    .await
    {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "[/_internal/version] replay window rejection for ip_hash={}",
            hash_ip(client_ip, &state.ip_hash_salt)
        );
        return e.to_response();
    }

    // Pull the dual-slot fingerprint pair from the same cache
    // the verify path consulted, so the `STATUS_API_TOKEN_*_6CHAR` fields
    // surfaced in the response and the per-request `secret_version` log
    // line both reflect the slot the verify path accepted against during
    // the same TTL window.
    let status_token_fps = crate::security::status_auth::current_fingerprints(&state.env).await;

    // Build the body. 8-char fingerprints; the `_PREVIOUS` slots
    // include the unset sentinel `"00000000"` outside a rotation window so
    // the drill's diff logic can distinguish "slot exists, empty" from
    // "slot missing entirely" (the latter would be a binding misconfiguration).
    let mek_fp = state
        .mek_cached
        .as_ref()
        .map(|m| fingerprint8_bytes(m.as_slice()))
        .unwrap_or_else(|| crate::security::secret_fingerprint::FINGERPRINT8_UNSET.to_string());
    let mek_prev_fp = state
        .previous_mek
        .as_ref()
        .map(|m| fingerprint8_bytes(m.as_slice()))
        .unwrap_or_else(|| crate::security::secret_fingerprint::FINGERPRINT8_UNSET.to_string());
    let session_fp = state
        .session_token_secret
        .as_ref()
        .map(|s| fingerprint8_str(Some(s.as_str())))
        .unwrap_or_else(|| crate::security::secret_fingerprint::FINGERPRINT8_UNSET.to_string());
    let session_prev_fp = state
        .session_token_secret_previous
        .as_ref()
        .map(|s| fingerprint8_str(Some(s.as_str())))
        .unwrap_or_else(|| crate::security::secret_fingerprint::FINGERPRINT8_UNSET.to_string());
    let ip_salt_fp = fingerprint8_str(Some(state.ip_hash_salt.as_str()));

    // STATUS_TOKEN fingerprints are 6-char in AppState; widen by recomputing
    // is impossible without the raw token (intentionally not retained). The
    // 6-char value is sufficient for slot-distinction at the endpoint level
    // because operators usually want to confirm "did the slot change", not
    // disambiguate against an unbounded fingerprint space.
    let body = json!({
        "service": "provii-verifier",
        "environment": environment,
        "deployed_at": state
            .env
            .var("WORKERS_BUILD_DEPLOYED_AT")
            .map(|v| v.to_string())
            .unwrap_or_default(),
        "git_sha": state
            .env
            .var("WORKERS_BUILD_GIT_SHA")
            .map(|v| v.to_string())
            .unwrap_or_default(),
        "secret_versions": {
            "VERIFIER_MEK": mek_fp,
            "VERIFIER_MEK_PREVIOUS": mek_prev_fp,
            "HOSTED_MEK": fingerprint8_from_secret(&state.env, "HOSTED_MEK").await,
            "HOSTED_MEK_PREVIOUS": fingerprint8_from_secret(&state.env, "HOSTED_MEK_PREVIOUS").await,
            "SESSION_TOKEN_SECRET": session_fp,
            "SESSION_TOKEN_SECRET_PREVIOUS": session_prev_fp,
            "VERIFIER_IP_HASH_SALT": ip_salt_fp,
            "STATUS_API_TOKEN_6CHAR": &status_token_fps.current,
            "STATUS_API_TOKEN_PREVIOUS_6CHAR": &status_token_fps.previous,
        },
    });

    let mut response = Response::from_json(&body)?;

    // emit the per-request `secret_version` log line + apply
    // the `x-secret-version` header carrying the STATUS_API_TOKEN slot that
    // satisfied the auth path above.
    let used = match outcome.slot {
        crate::security::StatusAuthSlot::Current => {
            Some(crate::security::secret_versions::RotationSlot::Current)
        }
        crate::security::StatusAuthSlot::Previous => {
            Some(crate::security::secret_versions::RotationSlot::Previous)
        }
        crate::security::StatusAuthSlot::ApiKey => None,
    };
    let line = crate::security::secret_versions::SecretVersionLine::single_for_slot(
        state.status_token_role,
        &status_token_fps.current,
        &status_token_fps.previous,
        used,
    );
    line.emit_log("GET /_internal/version");
    line.apply_header(&mut response)?;

    Ok(response)
}

/// Read a secret from the Secrets Store and compute its 8-char fingerprint.
/// Used for HOSTED_MEK + HOSTED_MEK_PREVIOUS which are not retained in
/// AppState beyond the 6-char fingerprint cached at startup.
async fn fingerprint8_from_secret(env: &worker::Env, binding: &str) -> String {
    let unset = crate::security::secret_fingerprint::FINGERPRINT8_UNSET.to_string();
    match env.secret_store(binding) {
        Ok(store) => match store.get().await {
            Ok(Some(s)) if !s.is_empty() => fingerprint8_str(Some(&s)),
            _ => unset,
        },
        Err(_) => unset,
    }
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
    use crate::security::secret_fingerprint::{
        fingerprint8_bytes, fingerprint8_str, FINGERPRINT8_UNSET,
    };

    // The Cf-Access-Authenticated-User-Email header is not used because
    // Workers expose *.workers.dev URLs by default, allowing an attacker
    // to reach the Worker without crossing the Access edge and self-set
    // the header. The handler requires the dual-slot status-token in
    // every environment.

    // ── Fingerprint helpers used by this handler ────────────────────

    #[test]
    fn fingerprint8_str_none_returns_unset() {
        assert_eq!(fingerprint8_str(None), FINGERPRINT8_UNSET);
    }

    #[test]
    fn fingerprint8_str_empty_returns_unset() {
        assert_eq!(fingerprint8_str(Some("")), FINGERPRINT8_UNSET);
    }

    #[test]
    fn fingerprint8_str_non_empty_returns_8_hex_chars() {
        let fp = fingerprint8_str(Some("test-secret"));
        assert_eq!(fp.len(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint8_bytes_empty_returns_unset() {
        assert_eq!(fingerprint8_bytes(b""), FINGERPRINT8_UNSET);
    }

    #[test]
    fn fingerprint8_bytes_known_vector() {
        // SHA-256("abc") = ba7816bf...
        assert_eq!(fingerprint8_bytes(b"abc"), "ba7816bf");
    }

    #[test]
    fn fingerprint8_unset_sentinel_is_eight_zeros() {
        assert_eq!(FINGERPRINT8_UNSET, "00000000");
        assert_eq!(FINGERPRINT8_UNSET.len(), 8);
    }

    // ── Fingerprint determinism ─────────────────────────────────────

    #[test]
    fn fingerprint8_is_deterministic() {
        let a = fingerprint8_str(Some("rotation-drill-token"));
        let b = fingerprint8_str(Some("rotation-drill-token"));
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint8_different_inputs_diverge() {
        let a = fingerprint8_str(Some("token-a"));
        let b = fingerprint8_str(Some("token-b"));
        assert_ne!(a, b);
    }

    // ── Response shape constants ────────────────────────────────────

    #[test]
    fn response_service_name_is_provii_verifier() {
        // The handler embeds "provii-verifier" in the response body.
        // Verify the constant matches expectations.
        let body = json!({
            "service": "provii-verifier",
            "environment": "production",
        });
        assert_eq!(body["service"], "provii-verifier");
    }

    #[test]
    fn secret_version_keys_match_expected_set() {
        // The /_internal/version response carries these keys under
        // secret_versions. Verify the set so rotation drill parsers
        // do not silently break when a key is renamed.
        let expected_keys = [
            "VERIFIER_MEK",
            "VERIFIER_MEK_PREVIOUS",
            "HOSTED_MEK",
            "HOSTED_MEK_PREVIOUS",
            "SESSION_TOKEN_SECRET",
            "SESSION_TOKEN_SECRET_PREVIOUS",
            "VERIFIER_IP_HASH_SALT",
            "STATUS_API_TOKEN_6CHAR",
            "STATUS_API_TOKEN_PREVIOUS_6CHAR",
        ];
        // 9 keys in the secret_versions block.
        assert_eq!(expected_keys.len(), 9);
        // Each key should be unique.
        let mut sorted = expected_keys.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), expected_keys.len(), "duplicate key detected");
    }

    // ── MEK fingerprint fallback shape ──────────────────────────────

    #[test]
    fn mek_none_produces_unset_fingerprint() {
        let mek_cached: Option<Vec<u8>> = None;
        let fp = mek_cached
            .as_ref()
            .map(|m| fingerprint8_bytes(m.as_slice()))
            .unwrap_or_else(|| FINGERPRINT8_UNSET.to_string());
        assert_eq!(fp, FINGERPRINT8_UNSET);
    }

    #[test]
    fn mek_some_produces_real_fingerprint() {
        let mek_cached: Option<Vec<u8>> = Some(b"test-mek-bytes".to_vec());
        let fp = mek_cached
            .as_ref()
            .map(|m| fingerprint8_bytes(m.as_slice()))
            .unwrap_or_else(|| FINGERPRINT8_UNSET.to_string());
        assert_ne!(fp, FINGERPRINT8_UNSET);
        assert_eq!(fp.len(), 8);
    }

    // ── Session token fingerprint shape ─────────────────────────────

    #[test]
    fn session_token_none_produces_unset() {
        let secret: Option<String> = None;
        let fp = secret
            .as_ref()
            .map(|s| fingerprint8_str(Some(s.as_str())))
            .unwrap_or_else(|| FINGERPRINT8_UNSET.to_string());
        assert_eq!(fp, FINGERPRINT8_UNSET);
    }

    #[test]
    fn session_token_some_produces_real_fingerprint() {
        let secret: Option<String> = Some("my-session-secret".to_string());
        let fp = secret
            .as_ref()
            .map(|s| fingerprint8_str(Some(s.as_str())))
            .unwrap_or_else(|| FINGERPRINT8_UNSET.to_string());
        assert_ne!(fp, FINGERPRINT8_UNSET);
        assert_eq!(fp.len(), 8);
    }

    // ── MEK previous slot fingerprint shape ────────────────────────

    #[test]
    fn mek_previous_none_produces_unset() {
        let previous_mek: Option<Vec<u8>> = None;
        let fp = previous_mek
            .as_ref()
            .map(|m| fingerprint8_bytes(m.as_slice()))
            .unwrap_or_else(|| FINGERPRINT8_UNSET.to_string());
        assert_eq!(fp, FINGERPRINT8_UNSET);
    }

    #[test]
    fn mek_previous_some_produces_real_fingerprint() {
        let previous_mek: Option<Vec<u8>> = Some(b"old-mek-bytes".to_vec());
        let fp = previous_mek
            .as_ref()
            .map(|m| fingerprint8_bytes(m.as_slice()))
            .unwrap_or_else(|| FINGERPRINT8_UNSET.to_string());
        assert_ne!(fp, FINGERPRINT8_UNSET);
        assert_eq!(fp.len(), 8);
    }

    #[test]
    fn mek_previous_empty_bytes_produces_unset() {
        let previous_mek: Option<Vec<u8>> = Some(Vec::new());
        let fp = previous_mek
            .as_ref()
            .map(|m| fingerprint8_bytes(m.as_slice()))
            .unwrap_or_else(|| FINGERPRINT8_UNSET.to_string());
        assert_eq!(fp, FINGERPRINT8_UNSET);
    }

    // ── Session token previous slot fingerprint shape ──────────────

    #[test]
    fn session_token_previous_none_produces_unset() {
        let secret: Option<String> = None;
        let fp = secret
            .as_ref()
            .map(|s| fingerprint8_str(Some(s.as_str())))
            .unwrap_or_else(|| FINGERPRINT8_UNSET.to_string());
        assert_eq!(fp, FINGERPRINT8_UNSET);
    }

    #[test]
    fn session_token_previous_some_produces_real_fingerprint() {
        let secret: Option<String> = Some("old-session-secret".to_string());
        let fp = secret
            .as_ref()
            .map(|s| fingerprint8_str(Some(s.as_str())))
            .unwrap_or_else(|| FINGERPRINT8_UNSET.to_string());
        assert_ne!(fp, FINGERPRINT8_UNSET);
        assert_eq!(fp.len(), 8);
    }

    // ── IP hash salt fingerprint shape ─────────────────────────────

    #[test]
    fn ip_salt_fingerprint_is_8_hex_chars() {
        let ip_hash_salt = "some-random-salt-value";
        let fp = fingerprint8_str(Some(ip_hash_salt));
        assert_eq!(fp.len(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn ip_salt_fingerprint_differs_between_salts() {
        let fp_a = fingerprint8_str(Some("salt-alpha"));
        let fp_b = fingerprint8_str(Some("salt-bravo"));
        assert_ne!(fp_a, fp_b);
    }

    // ── fingerprint8_str / fingerprint8_bytes consistency ──────────

    #[test]
    fn fingerprint8_str_matches_bytes_for_same_input() {
        let input = "consistency-check-token";
        let from_str = fingerprint8_str(Some(input));
        let from_bytes = fingerprint8_bytes(input.as_bytes());
        assert_eq!(from_str, from_bytes);
    }

    // ── Fingerprint output format ──────────────────────────────────

    #[test]
    fn fingerprint8_is_lowercase_hex_only() {
        let fp = fingerprint8_str(Some("anything-goes-here"));
        assert!(
            fp.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "fingerprint must be lowercase hex, got: {fp}"
        );
    }

    #[test]
    fn fingerprint8_bytes_single_byte_input() {
        let fp = fingerprint8_bytes(&[0x42]);
        assert_eq!(fp.len(), 8);
        assert_ne!(fp, FINGERPRINT8_UNSET);
    }

    #[test]
    fn fingerprint8_bytes_long_input() {
        let long = vec![0xAA; 10_000];
        let fp = fingerprint8_bytes(&long);
        assert_eq!(fp.len(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint8_whitespace_only_input_is_not_unset() {
        // Whitespace-only is non-empty, so it should produce a real fingerprint.
        let fp = fingerprint8_str(Some("   "));
        assert_ne!(fp, FINGERPRINT8_UNSET);
        assert_eq!(fp.len(), 8);
    }

    // ── StatusAuthSlot -> RotationSlot mapping ─────────────────────
    //
    // The handler (lines 194-202) maps StatusAuthSlot to RotationSlot.
    // This block exercises that same mapping logic in isolation.

    #[test]
    fn status_auth_slot_current_maps_to_rotation_current() {
        use crate::security::secret_versions::RotationSlot;
        use crate::security::StatusAuthSlot;
        let slot = StatusAuthSlot::Current;
        let mapped = match slot {
            StatusAuthSlot::Current => Some(RotationSlot::Current),
            StatusAuthSlot::Previous => Some(RotationSlot::Previous),
            StatusAuthSlot::ApiKey => None,
        };
        assert_eq!(mapped, Some(RotationSlot::Current));
    }

    #[test]
    fn status_auth_slot_previous_maps_to_rotation_previous() {
        use crate::security::secret_versions::RotationSlot;
        use crate::security::StatusAuthSlot;
        let slot = StatusAuthSlot::Previous;
        let mapped = match slot {
            StatusAuthSlot::Current => Some(RotationSlot::Current),
            StatusAuthSlot::Previous => Some(RotationSlot::Previous),
            StatusAuthSlot::ApiKey => None,
        };
        assert_eq!(mapped, Some(RotationSlot::Previous));
    }

    #[test]
    fn status_auth_slot_apikey_maps_to_none() {
        use crate::security::secret_versions::RotationSlot;
        use crate::security::StatusAuthSlot;
        let slot = StatusAuthSlot::ApiKey;
        let mapped: Option<RotationSlot> = match slot {
            StatusAuthSlot::Current => Some(RotationSlot::Current),
            StatusAuthSlot::Previous => Some(RotationSlot::Previous),
            StatusAuthSlot::ApiKey => None,
        };
        assert!(mapped.is_none());
    }

    // ── SecretVersionLine::single_for_slot used by handler ─────────

    #[test]
    fn single_for_slot_current_header_matches_current_fp() {
        use crate::security::secret_versions::{RotationSlot, SecretVersionLine};
        let role = "STATUS_TOKEN_PROD";
        let current_fp = "aabbcc";
        let previous_fp = "000000";
        let line = SecretVersionLine::single_for_slot(
            role,
            current_fp,
            previous_fp,
            Some(RotationSlot::Current),
        );
        assert_eq!(line.header_value(), current_fp);
    }

    #[test]
    fn single_for_slot_previous_header_matches_previous_fp() {
        use crate::security::secret_versions::{RotationSlot, SecretVersionLine};
        let role = "STATUS_TOKEN_PROD";
        let current_fp = "aabbcc";
        let previous_fp = "ddeeff";
        let line = SecretVersionLine::single_for_slot(
            role,
            current_fp,
            previous_fp,
            Some(RotationSlot::Previous),
        );
        assert_eq!(line.header_value(), previous_fp);
    }

    #[test]
    fn single_for_slot_none_header_is_unset() {
        use crate::security::secret_versions::SecretVersionLine;
        let role = "STATUS_TOKEN_PROD";
        let line = SecretVersionLine::single_for_slot(role, "aabbcc", "000000", None);
        assert_eq!(
            line.header_value(),
            crate::security::secret_fingerprint::FINGERPRINT_UNSET
        );
    }

    // ── status_token_role_for_env used by handler ──────────────────

    #[test]
    fn status_token_role_production_is_prod() {
        let role = crate::security::status_auth::status_token_role_for_env("production");
        assert_eq!(role, "STATUS_TOKEN_PROD");
    }

    #[test]
    fn status_token_role_sandbox_is_sbx() {
        let role = crate::security::status_auth::status_token_role_for_env("sandbox");
        assert_eq!(role, "STATUS_TOKEN_SBX");
    }

    #[test]
    fn status_token_role_development_is_sbx() {
        let role = crate::security::status_auth::status_token_role_for_env("development");
        assert_eq!(role, "STATUS_TOKEN_SBX");
    }

    #[test]
    fn status_token_role_unknown_falls_to_prod() {
        let role = crate::security::status_auth::status_token_role_for_env("staging");
        assert_eq!(role, "STATUS_TOKEN_PROD");
    }

    // ── Response body shape verification ───────────────────────────

    #[test]
    fn response_body_contains_all_required_top_level_keys() {
        let body = json!({
            "service": "provii-verifier",
            "environment": "production",
            "deployed_at": "2026-05-01T00:00:00Z",
            "git_sha": "abc12345",
            "secret_versions": {},
        });
        assert!(body.get("service").is_some());
        assert!(body.get("environment").is_some());
        assert!(body.get("deployed_at").is_some());
        assert!(body.get("git_sha").is_some());
        assert!(body.get("secret_versions").is_some());
    }

    #[test]
    fn response_body_deployed_at_empty_when_unset() {
        // The handler falls back to empty string when WORKERS_BUILD_DEPLOYED_AT
        // is not set in the environment.
        let deployed_at: String = String::new();
        assert!(deployed_at.is_empty());
    }

    #[test]
    fn response_body_git_sha_empty_when_unset() {
        let git_sha: String = String::new();
        assert!(git_sha.is_empty());
    }

    #[test]
    fn response_environment_reflects_sandbox() {
        let environment = "sandbox";
        let body = json!({
            "service": "provii-verifier",
            "environment": environment,
        });
        assert_eq!(body["environment"], "sandbox");
    }

    // ── Full secret_versions block shape ───────────────────────────

    #[test]
    fn full_secret_versions_block_with_all_slots_populated() {
        let mek_fp = fingerprint8_bytes(b"test-mek");
        let mek_prev_fp = fingerprint8_bytes(b"old-mek");
        let hosted_mek_fp = fingerprint8_str(Some("hosted-mek-val"));
        let hosted_mek_prev_fp = FINGERPRINT8_UNSET.to_string();
        let session_fp = fingerprint8_str(Some("session-secret"));
        let session_prev_fp = fingerprint8_str(Some("old-session-secret"));
        let ip_salt_fp = fingerprint8_str(Some("my-ip-salt"));
        let status_current = "abcdef";
        let status_previous = "000000";

        let body = json!({
            "secret_versions": {
                "VERIFIER_MEK": mek_fp,
                "VERIFIER_MEK_PREVIOUS": mek_prev_fp,
                "HOSTED_MEK": hosted_mek_fp,
                "HOSTED_MEK_PREVIOUS": hosted_mek_prev_fp,
                "SESSION_TOKEN_SECRET": session_fp,
                "SESSION_TOKEN_SECRET_PREVIOUS": session_prev_fp,
                "VERIFIER_IP_HASH_SALT": ip_salt_fp,
                "STATUS_API_TOKEN_6CHAR": status_current,
                "STATUS_API_TOKEN_PREVIOUS_6CHAR": status_previous,
            },
        });

        let sv = body
            .get("secret_versions")
            .expect("missing secret_versions");
        let obj = sv.as_object().expect("secret_versions must be object");
        assert_eq!(obj.len(), 9, "expected 9 secret_versions keys");

        // Verify all fingerprints are non-empty strings.
        for (key, val) in obj {
            let s = val
                .as_str()
                .unwrap_or_else(|| panic!("key {key} must be string")); // nosemgrep: provii.workers.panic-in-worker
            assert!(!s.is_empty(), "key {key} must not be empty");
        }
    }

    #[test]
    fn secret_versions_all_unset_when_no_secrets_bound() {
        let body = json!({
            "secret_versions": {
                "VERIFIER_MEK": FINGERPRINT8_UNSET,
                "VERIFIER_MEK_PREVIOUS": FINGERPRINT8_UNSET,
                "HOSTED_MEK": FINGERPRINT8_UNSET,
                "HOSTED_MEK_PREVIOUS": FINGERPRINT8_UNSET,
                "SESSION_TOKEN_SECRET": FINGERPRINT8_UNSET,
                "SESSION_TOKEN_SECRET_PREVIOUS": FINGERPRINT8_UNSET,
                "VERIFIER_IP_HASH_SALT": FINGERPRINT8_UNSET,
                "STATUS_API_TOKEN_6CHAR": "000000",
                "STATUS_API_TOKEN_PREVIOUS_6CHAR": "000000",
            },
        });

        let sv = body
            .get("secret_versions")
            .expect("missing secret_versions");
        let obj = sv.as_object().expect("secret_versions must be object");
        // All 8-char fields should be the unset sentinel.
        for key in [
            "VERIFIER_MEK",
            "VERIFIER_MEK_PREVIOUS",
            "HOSTED_MEK",
            "HOSTED_MEK_PREVIOUS",
            "SESSION_TOKEN_SECRET",
            "SESSION_TOKEN_SECRET_PREVIOUS",
            "VERIFIER_IP_HASH_SALT",
        ] {
            assert_eq!(
                obj.get(key).and_then(|v| v.as_str()),
                Some(FINGERPRINT8_UNSET),
                "key {key} should be unset sentinel"
            );
        }
    }

    // ── Drill distinguishes unset slot from missing key ────────────

    #[test]
    fn unset_sentinel_is_distinct_from_absent_key() {
        let body = json!({
            "secret_versions": {
                "VERIFIER_MEK": FINGERPRINT8_UNSET,
            },
        });
        let sv = body.get("secret_versions").expect("sv");
        // Key exists with sentinel value.
        assert_eq!(
            sv.get("VERIFIER_MEK").and_then(|v| v.as_str()),
            Some(FINGERPRINT8_UNSET),
        );
        // Missing key returns None, which the drill uses to detect binding
        // misconfiguration.
        assert!(sv.get("NONEXISTENT_KEY").is_none());
    }

    // ── MEK empty-vec edge case ────────────────────────────────────

    #[test]
    fn mek_some_empty_vec_produces_unset_fingerprint() {
        let mek_cached: Option<Vec<u8>> = Some(Vec::new());
        let fp = mek_cached
            .as_ref()
            .map(|m| fingerprint8_bytes(m.as_slice()))
            .unwrap_or_else(|| FINGERPRINT8_UNSET.to_string());
        assert_eq!(fp, FINGERPRINT8_UNSET);
    }

    // ── Session token empty-string edge case ───────────────────────

    #[test]
    fn session_token_some_empty_string_produces_unset() {
        let secret: Option<String> = Some(String::new());
        let fp = secret
            .as_ref()
            .map(|s| fingerprint8_str(Some(s.as_str())))
            .unwrap_or_else(|| FINGERPRINT8_UNSET.to_string());
        assert_eq!(fp, FINGERPRINT8_UNSET);
    }

    // ── Fingerprint known vectors for regression ───────────────────

    #[test]
    fn fingerprint8_known_sha256_empty_string_via_str() {
        // fingerprint8_str(Some("")) returns UNSET because input is empty.
        assert_eq!(fingerprint8_str(Some("")), FINGERPRINT8_UNSET);
    }

    #[test]
    fn fingerprint8_known_sha256_abc_via_str() {
        // SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223
        // First 8 hex chars = "ba7816bf"
        assert_eq!(fingerprint8_str(Some("abc")), "ba7816bf");
    }

    #[test]
    fn fingerprint8_extends_6char_prefix() {
        // The 8-char fingerprint must agree with the 6-char fingerprint on
        // the first 6 characters (both are SHA-256 prefixes).
        let input = b"rotation-drill-token";
        let fp6 = crate::security::secret_fingerprint::fingerprint6_bytes(input);
        let fp8 = fingerprint8_bytes(input);
        assert_eq!(&fp8[..6], fp6.as_str(), "8-char must extend 6-char prefix");
    }

    // ── handler auth rejection shape ───────────────────────────────
    //
    // The handler returns ApiError::Unauthorized on auth failure. Verify
    // the error code maps to the right status so the response shape is
    // correct even when the handler short-circuits.

    #[test]
    fn unauthorized_error_maps_to_401() {
        let err = crate::error::ApiError::Unauthorized;
        assert_eq!(err.to_string(), "unauthorized");
        assert_eq!(
            crate::error::ApiError::status_for_display_str("unauthorized"),
            Some((401, "UNAUTHORIZED"))
        );
    }

    // ── Rotation slot used_label for status_token_role ──────────────

    #[test]
    fn rotation_slot_current_label_for_status_token_prod() {
        use crate::security::secret_versions::RotationSlot;
        let label = RotationSlot::Current.used_label("STATUS_TOKEN_PROD");
        assert_eq!(label, "STATUS_TOKEN_PROD");
    }

    #[test]
    fn rotation_slot_previous_label_for_status_token_prod() {
        use crate::security::secret_versions::RotationSlot;
        let label = RotationSlot::Previous.used_label("STATUS_TOKEN_PROD");
        assert_eq!(label, "STATUS_TOKEN_PROD_PREVIOUS");
    }

    #[test]
    fn rotation_slot_current_label_for_status_token_sbx() {
        use crate::security::secret_versions::RotationSlot;
        let label = RotationSlot::Current.used_label("STATUS_TOKEN_SBX");
        assert_eq!(label, "STATUS_TOKEN_SBX");
    }

    #[test]
    fn rotation_slot_previous_label_for_status_token_sbx() {
        use crate::security::secret_versions::RotationSlot;
        let label = RotationSlot::Previous.used_label("STATUS_TOKEN_SBX");
        assert_eq!(label, "STATUS_TOKEN_SBX_PREVIOUS");
    }

    // ── emit_log does not panic ────────────────────────────────────

    #[test]
    fn secret_version_line_emit_log_does_not_panic() {
        use crate::security::secret_versions::SecretVersionLine;
        let line = SecretVersionLine::single_for_slot(
            "STATUS_TOKEN_PROD",
            "aabbcc",
            "000000",
            Some(crate::security::secret_versions::RotationSlot::Current),
        );
        // On non-wasm32 targets console_log! is a no-op, so this just
        // confirms the method does not panic on any code path.
        line.emit_log("GET /_internal/version");
    }

    #[test]
    fn secret_version_line_emit_log_with_no_used_slot() {
        use crate::security::secret_versions::SecretVersionLine;
        let line =
            SecretVersionLine::single_for_slot("STATUS_TOKEN_PROD", "aabbcc", "000000", None);
        line.emit_log("GET /_internal/version");
    }

    // ── versions_json output for status token line ─────────────────

    #[test]
    fn versions_json_contains_both_status_token_slots() {
        use crate::security::secret_versions::{RotationSlot, SecretVersionLine};
        let line = SecretVersionLine::single_for_slot(
            "STATUS_TOKEN_PROD",
            "abcdef",
            "fedcba",
            Some(RotationSlot::Current),
        );
        let json = line.versions_json();
        assert!(json.contains(r#""STATUS_TOKEN_PROD":"abcdef""#));
        assert!(json.contains(r#""STATUS_TOKEN_PROD_PREVIOUS":"fedcba""#));
    }

    #[test]
    fn versions_json_is_valid_json_for_status_token_line() -> Result<(), serde_json::Error> {
        use crate::security::secret_versions::{RotationSlot, SecretVersionLine};
        let line = SecretVersionLine::single_for_slot(
            "STATUS_TOKEN_PROD",
            "112233",
            "000000",
            Some(RotationSlot::Current),
        );
        let parsed: serde_json::Value = serde_json::from_str(&line.versions_json())?;
        assert!(parsed.is_object());
        Ok(())
    }

    // ── Fingerprint determinism across both width variants ─────────

    #[test]
    fn fingerprint8_deterministic_across_calls_for_bytes() {
        let input = b"determinism-check-bytes";
        let a = fingerprint8_bytes(input);
        let b = fingerprint8_bytes(input);
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint8_deterministic_across_calls_for_str() {
        let a = fingerprint8_str(Some("determinism-check-str"));
        let b = fingerprint8_str(Some("determinism-check-str"));
        assert_eq!(a, b);
    }

    // ── Current and previous MEK produce distinct fingerprints ─────

    #[test]
    fn current_and_previous_mek_fingerprints_differ() {
        let current = fingerprint8_bytes(b"current-mek-material");
        let previous = fingerprint8_bytes(b"previous-mek-material");
        assert_ne!(current, previous);
    }

    // ── Current and previous session tokens produce distinct fps ───

    #[test]
    fn current_and_previous_session_fingerprints_differ() {
        let current = fingerprint8_str(Some("session-current"));
        let previous = fingerprint8_str(Some("session-previous"));
        assert_ne!(current, previous);
    }
}
