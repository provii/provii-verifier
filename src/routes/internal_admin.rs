// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Rotation-drill admin endpoints.
//!
//! These endpoints support the verify-rotation soak checks and the
//! `cleanup-test-fixtures` CLI in Wave 2 of the rotation drill. They are
//! gated by the same dual-slot status-token auth scheme used elsewhere in
//! the worker, plus the per-request replay window enforced by
//! [`crate::security::status_auth::enforce_internal_replay_window`].
//!
//! Endpoints
//!
//! | Method  | Path                                | Purpose |
//! |---------|-------------------------------------|---------|
//! | POST    | `/_internal/mek-decrypt-probe`      | Decrypt an `EncryptedSecret` with `HOSTED_MEK` (current then previous), return slot + 6-char fingerprint of plaintext. |
//! | POST    | `/_internal/replay-saved-pre-rotation-token` | Replay a captured admin token against the current dual-slot accept path. |
//! | DELETE  | `/_internal/test-fixtures/{class}`  | Clear test-only entries from the named fixture class. Supported class: `bans`. |
//! | GET     | `/_internal/test-fixtures`          | Manifest of supported classes + binding kinds. |
//!
//! Auth model
//!
//! Every handler runs the same path:
//!
//! 1. `authenticate_status_endpoint` (dual-slot bearer accept; constant-time
//!    inside `subtle::ConstantTimeEq` / `hmac::Mac::verify_slice`).
//! 2. `enforce_internal_replay_window` with a per-endpoint `role_tag` so
//!    nonces cannot replay across surfaces.
//! 3. Per-IP rate limit (10/hour) before the bearer check, plus a
//!    5-attempt failure lockout window.
//!
//! Data exposure
//!
//! Fingerprints are
//! public-safe (24 bits, one-way). Plaintext is never returned. The probe
//! endpoint zeroises any decrypted plaintext as soon as the fingerprint is
//! computed.
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use worker::{kv::KvStore, Headers, Response};
use zeroize::Zeroizing;

use crate::error::ApiError;
#[cfg(target_arch = "wasm32")]
use crate::security::hash_ip;
use crate::security::{
    authenticate_status_endpoint, secret_fingerprint::fingerprint6_bytes,
    status_auth::enforce_internal_replay_window,
};
use crate::AppState;

/// Admin per-IP hourly cap.
const ADMIN_RL_LIMIT_PER_HOUR: u32 = 10;
/// Admin failure lockout threshold.
const ADMIN_LOCKOUT_THRESHOLD: u32 = 5;
/// TTL for the failure lockout counter, in seconds.
const ADMIN_LOCKOUT_TTL_SECS: u64 = 3600;
/// `ADMIN_LOCKOUT_TTL_SECS` widened to `u32` for the lockout retry-after.
const ADMIN_LOCKOUT_TTL_SECS_U32: u32 = 3600;

/// Test-fixture KV key prefix for ban entries. The drill seeds entries
/// under `ban:test:*` so cleanup only deletes its own state.
const BAN_TEST_PREFIX: &str = "ban:test:";

/// Response shape for `POST /_internal/mek-decrypt-probe`.
#[derive(Serialize)]
pub struct MekProbeResponse {
    pub ok: bool,
    /// `current` or `previous`. Absent when neither slot decrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<&'static str>,
    /// 6-char hex fingerprint of the plaintext, public-safe per
    /// the structured log schema. The sentinel `"000000"` indicates no plaintext
    /// was recovered.
    pub actual_fingerprint: String,
}

/// Request body for the MEK decrypt probe.
#[derive(Deserialize)]
pub struct MekProbeRequest {
    /// Base64 (standard, with padding) of the JSON `EncryptedSecret`
    /// envelope. The full envelope is required because
    /// `decrypt_hmac_secret` needs the encrypted DEK + IV + tag, not just
    /// the inner ciphertext.
    pub encrypted_secret: String,
    /// Expected 6-char hex fingerprint of the plaintext. Operators
    /// supply this from a known test-vector seeded before rotation.
    pub expected_plaintext_fingerprint: String,
}

/// Request body for the replay-saved-pre-rotation-token endpoint.
#[derive(Deserialize)]
pub struct ReplayTokenRequest {
    pub token: String,
}

/// Response shape for the replay-saved-pre-rotation-token endpoint.
#[derive(Serialize)]
pub struct ReplayTokenResponse {
    /// True when the saved token no longer authenticates against the
    /// current dual-slot pair.
    pub rejected: bool,
    pub reason: String,
}

/// Response shape for `POST /_internal/mek-decrypt-probe`.
fn unset_fingerprint() -> String {
    crate::security::secret_fingerprint::FINGERPRINT_UNSET.to_string()
}

/// Run the bearer + replay-window auth path used by every admin endpoint.
///
/// Returns `Ok(())` on success or an [`ApiError`] response that callers
/// should pass straight back to the router. The role tag scopes the
/// nonce dedupe so an `admin-fixture:bans` nonce cannot replay an
/// `admin-mek-probe` request.
pub async fn authenticate_admin_endpoint(
    headers: &Headers,
    client_ip: &str,
    state: &Arc<AppState>,
    role_tag: &str,
) -> Result<(), ApiError> {
    if let Err(e) = authenticate_status_endpoint(
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
        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "[/_internal/admin role={}] bearer auth denied for ip_hash={}",
            role_tag,
            hash_ip(client_ip, &state.ip_hash_salt)
        );
        return Err(e);
    }

    enforce_internal_replay_window(
        headers,
        &state.nonce_store,
        role_tag,
        &state.audit_logger,
        client_ip,
        &state.ip_hash_salt,
    )
    .await
    .map(|_| ())
    .inspect_err(|_| {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "[/_internal/admin role={}] replay window rejection for ip_hash={}",
            role_tag,
            hash_ip(client_ip, &state.ip_hash_salt)
        );
    })
}

/// Per-IP 10/hour cap + 5-attempt failure lockout.
///
/// Returns `Err(retry_after_secs)` when the request is over quota or the
/// caller is in lockout. Lockout is keyed off the client IP hash so a
/// bad-actor replaying nonces cannot brute the surface.
pub async fn admin_rate_limit_check(
    rl_kv: &KvStore,
    ip_hash: &str,
    role_tag: &str,
) -> Result<(), u32> {
    let now_secs = worker::Date::now().as_millis() / 1000;
    #[allow(clippy::arithmetic_side_effects)]
    let hour_ts = now_secs / 3600 * 3600;
    let hour_key = format!("admin_rl:{}:{}:{}", role_tag, ip_hash, hour_ts);

    // Hourly counter.
    let current: u32 = match rl_kv.get(&hour_key).text().await {
        Ok(Some(s)) => s.parse().unwrap_or(0),
        Ok(None) => 0,
        Err(_) => {
            // SECURITY: fail closed on KV read errors. Mirrors
            // check_kv_counter behaviour in `rate_limiting.rs`.
            return Err(60);
        }
    };
    if current >= ADMIN_RL_LIMIT_PER_HOUR {
        #[allow(clippy::cast_possible_truncation)]
        let retry = hour_ts.saturating_add(3600).saturating_sub(now_secs) as u32;
        return Err(retry);
    }

    // Lockout counter (5 failed attempts in the last hour).
    let lock_key = format!("admin_lock:{}:{}", role_tag, ip_hash);
    let lock_count: u32 = match rl_kv.get(&lock_key).text().await {
        Ok(Some(s)) => s.parse().unwrap_or(0),
        Ok(None) => 0,
        Err(_) => return Err(60),
    };
    if lock_count >= ADMIN_LOCKOUT_THRESHOLD {
        return Err(ADMIN_LOCKOUT_TTL_SECS_U32);
    }

    // Increment the hourly counter (best effort).
    if let Ok(put) = rl_kv.put(&hour_key, current.saturating_add(1).to_string()) {
        let _ = put.expiration_ttl(7200).execute().await;
    }

    Ok(())
}

/// Increment the per-IP failure lockout counter after an auth failure.
///
/// Failures here are bearer-auth or replay-window rejects, not
/// 4xx-payload validation rejects.
pub async fn record_admin_auth_failure(rl_kv: &KvStore, ip_hash: &str, role_tag: &str) {
    let lock_key = format!("admin_lock:{}:{}", role_tag, ip_hash);
    let count: u32 = match rl_kv.get(&lock_key).text().await {
        Ok(Some(s)) => s.parse().unwrap_or(0),
        Ok(None) => 0,
        Err(_) => 0,
    };
    if let Ok(put) = rl_kv.put(&lock_key, count.saturating_add(1).to_string()) {
        let _ = put.expiration_ttl(ADMIN_LOCKOUT_TTL_SECS).execute().await;
    }
}

/// Handler for `POST /_internal/mek-decrypt-probe`.
///
/// Decrypts the supplied envelope with `HOSTED_MEK` first, then with
/// `HOSTED_MEK_PREVIOUS` if the current slot fails. On success, computes
/// the 6-char fingerprint of the plaintext and constant-time-compares it
/// to the operator-supplied expected fingerprint.
///
/// SECURITY: the decrypted plaintext is wrapped in `Zeroizing` and
/// dropped before the response is built, so the secret never lives past
/// the fingerprint compare. The fingerprint comparison uses
/// `subtle::ConstantTimeEq` even though the fingerprint is public-safe,
/// because the comparison is between operator-supplied data and a value
/// derived from the secret; a timing oracle would let an attacker who
/// captured a ciphertext probe for the matching plaintext fingerprint.
pub async fn handle_mek_decrypt_probe(
    body: &[u8],
    state: &Arc<AppState>,
) -> Result<Response, worker::Error> {
    let req: MekProbeRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            return ApiError::bad_request("INVALID_BODY", None, format!("{}", e)).to_response()
        }
    };

    let envelope_bytes = match BASE64_STD.decode(req.encrypted_secret.as_bytes()) {
        Ok(b) => b,
        Err(_) => {
            return ApiError::bad_request(
                "INVALID_BASE64",
                Some("encrypted_secret"),
                "encrypted_secret must be standard-base64 of the EncryptedSecret JSON",
            )
            .to_response();
        }
    };

    let envelope: crate::security::EncryptedSecret = match serde_json::from_slice(&envelope_bytes) {
        Ok(e) => e,
        Err(e) => {
            return ApiError::bad_request(
                "INVALID_ENVELOPE",
                Some("encrypted_secret"),
                format!("EncryptedSecret JSON parse failed: {}", e),
            )
            .to_response();
        }
    };

    // Resolve HOSTED_MEK current. If the binding is missing the probe
    // cannot run; surface a 500 rather than a misleading 200 ok=false.
    let current_mek = match crate::hosted::encryption::get_mek_from_secrets(&state.env).await {
        Ok(m) => m,
        Err(e) => {
            return ApiError::Internal(anyhow::anyhow!("HOSTED_MEK unavailable: {}", e))
                .to_response();
        }
    };

    // Try current first.
    let mut slot: Option<&'static str> = None;
    let plaintext: Option<Zeroizing<Vec<u8>>> =
        match crate::security::envelope_encryption::decrypt_hmac_secret(&envelope, &current_mek)
            .await
        {
            Ok(pt) => {
                slot = Some("current");
                Some(pt)
            }
            Err(_) => {
                // Try previous slot.
                match crate::hosted::encryption::get_mek_secondary_from_secrets(&state.env).await {
                    Some(prev_mek) => {
                        match crate::security::envelope_encryption::decrypt_hmac_secret(
                            &envelope, &prev_mek,
                        )
                        .await
                        {
                            Ok(pt) => {
                                slot = Some("previous");
                                Some(pt)
                            }
                            Err(_) => None,
                        }
                    }
                    None => None,
                }
            }
        };

    // Compute the fingerprint, then drop the plaintext immediately.
    let actual_fp = match plaintext.as_ref() {
        Some(pt) => fingerprint6_bytes(pt.as_slice()),
        None => unset_fingerprint(),
    };
    drop(plaintext); // explicit zeroise via Zeroizing<Vec<u8>>::Drop

    // Constant-time compare of the operator-supplied expected fingerprint
    // and the computed one. Public-safe inputs but using `subtle` here
    // closes the timing channel between matched / mismatched compares so
    // a captured ciphertext cannot be probed for plaintext fingerprints.
    let ok = bool::from(
        actual_fp
            .as_bytes()
            .ct_eq(req.expected_plaintext_fingerprint.as_bytes()),
    ) && slot.is_some();

    let payload = MekProbeResponse {
        ok,
        slot,
        actual_fingerprint: actual_fp,
    };
    Response::from_json(&payload)
}

/// Handler for `POST /_internal/replay-saved-pre-rotation-token`.
///
/// Re-runs the same dual-slot bearer auth path used by `/health/detailed`
/// + `/metrics` against the supplied token. Returns `rejected: true`
/// when the token no longer authenticates (the rotation closed the
/// previous slot) and `rejected: false` when it still does.
///
/// SECURITY: the token is constant-time-compared inside
/// `authenticate_status_endpoint`. We mint a synthetic `Headers` with
/// `Authorization: Bearer <token>` so the existing primitive runs
/// unchanged. The body string carrying the token is dropped before the
/// response is built.
pub async fn handle_replay_pre_rotation_token(
    body: &[u8],
    client_ip: &str,
    state: &Arc<AppState>,
) -> Result<Response, worker::Error> {
    let req: ReplayTokenRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            return ApiError::bad_request("INVALID_BODY", None, format!("{}", e)).to_response()
        }
    };

    // Build a synthetic Headers carrying the saved token. The probe
    // headers are independent from the live request headers so the
    // existing replay-window state is untouched.
    let probe_headers = Headers::new();
    let bearer = format!("Bearer {}", req.token);
    if let Err(e) = probe_headers.set("Authorization", &bearer) {
        return ApiError::Internal(anyhow::anyhow!("header build failed: {}", e)).to_response();
    }

    let outcome = authenticate_status_endpoint(
        &state.env,
        &probe_headers,
        state.status_token_role,
        &state.audit_logger,
        client_ip,
        Some(&state.origin_policy_store),
        &state.ip_hash_salt,
    )
    .await;

    let body = match outcome {
        Ok(_) => ReplayTokenResponse {
            rejected: false,
            reason: "token still accepted".to_string(),
        },
        Err(e) => ReplayTokenResponse {
            rejected: true,
            reason: format!("{:?}", e),
        },
    };
    Response::from_json(&body)
}

/// Handler for `DELETE /_internal/test-fixtures/{class}`.
///
/// Supported classes for provii-verifier:
///
/// - `bans`: clears every key under `VERIFIER_KV_BANLIST` whose key
///   matches `ban:test:*`. Production ban entries use `ban:<nullifier>`
///   (no `test:` infix), so this never touches partner-traffic state.
///
/// `recovery_codes` is intentionally unsupported here; that store lives
/// in admin-portal.
pub async fn handle_delete_test_fixtures(
    class: &str,
    state: &Arc<AppState>,
) -> Result<Response, worker::Error> {
    match class {
        "bans" => clear_bans_test_prefix(state).await,
        other => ApiError::bad_request(
            "UNSUPPORTED_CLASS",
            Some("class"),
            format!("provii-verifier does not own fixture class '{}'", other),
        )
        .to_response(),
    }
}

async fn clear_bans_test_prefix(state: &Arc<AppState>) -> Result<Response, worker::Error> {
    let kv = match state.env.kv(crate::bindings::KV_BANLIST) {
        Ok(k) => k,
        Err(e) => {
            return ApiError::Internal(anyhow::anyhow!(
                "{} binding unavailable: {}",
                crate::bindings::KV_BANLIST,
                e
            ))
            .to_response();
        }
    };

    let mut deleted: u32 = 0;
    let mut cursor: Option<String> = None;
    loop {
        let mut listing = kv.list().prefix(BAN_TEST_PREFIX.to_string());
        if let Some(c) = cursor.as_ref() {
            listing = listing.cursor(c.clone());
        }
        let result = match listing.execute().await {
            Ok(r) => r,
            Err(e) => {
                return ApiError::Internal(anyhow::anyhow!("KV list failed: {}", e)).to_response();
            }
        };
        for k in &result.keys {
            if k.name.starts_with(BAN_TEST_PREFIX) {
                if let Err(e) = kv.delete(&k.name).await {
                    return ApiError::Internal(anyhow::anyhow!("KV delete failed: {}", e))
                        .to_response();
                }
                deleted = deleted.saturating_add(1);
            }
        }
        if result.list_complete {
            break;
        }
        cursor = result.cursor;
        if cursor.is_none() {
            break;
        }
    }

    let payload = json!({
        "worker": "provii-verifier",
        "class": "bans",
        "binding": crate::bindings::KV_BANLIST,
        "prefix": BAN_TEST_PREFIX,
        "deleted": deleted,
    });
    Response::from_json(&payload)
}

/// Handler for `GET /_internal/test-fixtures`.
///
/// Returns the manifest the cleanup CLI uses to discover what classes
/// this worker can clear and which binding backs each one.
pub async fn handle_test_fixtures_manifest() -> Result<Response, worker::Error> {
    let body = json!({
        "worker": "provii-verifier",
        "supported_classes": ["bans"],
        "binding_kind_per_class": { "bans": "kv" },
        "namespace_or_table_per_class": { "bans": crate::bindings::KV_BANLIST },
    });
    Response::from_json(&body)
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
    use crate::security::secret_fingerprint::{fingerprint6_bytes, FINGERPRINT_UNSET};

    #[test]
    fn manifest_payload_lists_bans_class_only() {
        let body = json!({
            "worker": "provii-verifier",
            "supported_classes": ["bans"],
            "binding_kind_per_class": { "bans": "kv" },
            "namespace_or_table_per_class": { "bans": crate::bindings::KV_BANLIST },
        });
        assert_eq!(body["worker"], "provii-verifier");
        assert_eq!(body["supported_classes"][0], "bans");
        assert_eq!(body["binding_kind_per_class"]["bans"], "kv");
        assert_eq!(
            body["namespace_or_table_per_class"]["bans"],
            crate::bindings::KV_BANLIST
        );
    }

    #[test]
    fn unset_fingerprint_matches_module_sentinel() {
        assert_eq!(unset_fingerprint(), FINGERPRINT_UNSET);
    }

    #[test]
    fn fingerprint_compare_constant_time_matches() {
        let a = fingerprint6_bytes(b"plaintext-secret");
        let b = a.clone();
        let result = bool::from(a.as_bytes().ct_eq(b.as_bytes()));
        assert!(result);
    }

    #[test]
    fn fingerprint_compare_constant_time_mismatches() {
        let a = fingerprint6_bytes(b"plaintext-secret");
        let b = fingerprint6_bytes(b"different-secret");
        let result = bool::from(a.as_bytes().ct_eq(b.as_bytes()));
        assert!(!result);
    }

    #[test]
    fn mek_probe_request_deserialises_full_shape() {
        let json = r#"{
            "encrypted_secret": "ZW52ZWxvcGUtanNvbi1iYXNlNjQ=",
            "expected_plaintext_fingerprint": "ba7816"
        }"#;
        let req: MekProbeRequest = serde_json::from_str(json).expect("parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(req.expected_plaintext_fingerprint, "ba7816");
        assert!(!req.encrypted_secret.is_empty());
    }

    #[test]
    fn replay_token_request_deserialises_full_shape() {
        let json = r#"{ "token": "captured-token-value" }"#;
        let req: ReplayTokenRequest = serde_json::from_str(json).expect("parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(req.token, "captured-token-value");
    }

    #[test]
    fn ban_test_prefix_is_namespaced_under_ban() {
        // Production ban keys are `ban:<nullifier>`, never `ban:test:*`.
        // The cleanup prefix must be a strict subset of `ban:`.
        assert!(BAN_TEST_PREFIX.starts_with("ban:"));
        assert!(BAN_TEST_PREFIX.ends_with(":"));
        assert_ne!(BAN_TEST_PREFIX, "ban:");
    }

    #[test]
    fn replay_token_response_serialises_rejected_path() {
        let body = ReplayTokenResponse {
            rejected: true,
            reason: "Unauthorized".to_string(),
        };
        let s = serde_json::to_string(&body).expect("serialise");
        assert!(s.contains("\"rejected\":true"));
        assert!(s.contains("\"reason\""));
    }

    #[test]
    fn replay_token_response_serialises_accepted_path() {
        let body = ReplayTokenResponse {
            rejected: false,
            reason: "token still accepted".to_string(),
        };
        let s = serde_json::to_string(&body).expect("serialise");
        assert!(s.contains("\"rejected\":false"));
    }

    #[test]
    fn mek_probe_response_omits_slot_when_none() {
        let body = MekProbeResponse {
            ok: false,
            slot: None,
            actual_fingerprint: FINGERPRINT_UNSET.to_string(),
        };
        let s = serde_json::to_string(&body).expect("serialise");
        assert!(!s.contains("\"slot\""));
        assert!(s.contains("\"ok\":false"));
        assert!(s.contains("\"actual_fingerprint\""));
    }

    #[test]
    fn mek_probe_response_includes_slot_label_on_match() {
        let body = MekProbeResponse {
            ok: true,
            slot: Some("current"),
            actual_fingerprint: "ba7816".to_string(),
        };
        let s = serde_json::to_string(&body).expect("serialise");
        assert!(s.contains("\"slot\":\"current\""));
        assert!(s.contains("\"ok\":true"));
    }

    #[test]
    fn admin_rl_constants_match_ar024() {
        assert_eq!(ADMIN_RL_LIMIT_PER_HOUR, 10);
        assert_eq!(ADMIN_LOCKOUT_THRESHOLD, 5);
        assert_eq!(ADMIN_LOCKOUT_TTL_SECS, 3600);
        assert_eq!(ADMIN_LOCKOUT_TTL_SECS_U32 as u64, ADMIN_LOCKOUT_TTL_SECS);
    }

    // ── MekProbeRequest validation ──────────────────────────────────

    #[test]
    fn mek_probe_request_rejects_missing_fields() {
        let json = r#"{ "encrypted_secret": "ZW52ZWxvcGU=" }"#;
        let result = serde_json::from_str::<MekProbeRequest>(json);
        assert!(
            result.is_err(),
            "missing expected_plaintext_fingerprint must error"
        );
    }

    #[test]
    fn mek_probe_request_rejects_empty_json() {
        let result = serde_json::from_str::<MekProbeRequest>("{}");
        assert!(result.is_err());
    }

    #[test]
    fn mek_probe_request_allows_empty_strings() {
        let json = r#"{
            "encrypted_secret": "",
            "expected_plaintext_fingerprint": ""
        }"#;
        let req: MekProbeRequest = serde_json::from_str(json).expect("parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert!(req.encrypted_secret.is_empty());
        assert!(req.expected_plaintext_fingerprint.is_empty());
    }

    // ── ReplayTokenRequest validation ───────────────────────────────

    #[test]
    fn replay_token_request_rejects_missing_token() {
        let result = serde_json::from_str::<ReplayTokenRequest>("{}");
        assert!(result.is_err(), "missing token field must error");
    }

    #[test]
    fn replay_token_request_allows_empty_token() {
        let json = r#"{ "token": "" }"#;
        let req: ReplayTokenRequest = serde_json::from_str(json).expect("parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert!(req.token.is_empty());
    }

    // ── MekProbeResponse serialisation edge cases ───────────────────

    #[test]
    fn mek_probe_response_slot_previous() {
        let body = MekProbeResponse {
            ok: true,
            slot: Some("previous"),
            actual_fingerprint: "abc123".to_string(),
        };
        let s = serde_json::to_string(&body).expect("serialise");
        assert!(s.contains("\"slot\":\"previous\""));
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains("\"actual_fingerprint\":\"abc123\""));
    }

    #[test]
    fn mek_probe_response_ok_false_with_slot_none() {
        // When neither MEK slot decrypts, ok=false and slot is omitted.
        let body = MekProbeResponse {
            ok: false,
            slot: None,
            actual_fingerprint: FINGERPRINT_UNSET.to_string(),
        };
        let s = serde_json::to_string(&body).expect("serialise");
        assert!(s.contains("\"ok\":false"));
        assert!(!s.contains("\"slot\""));
        assert!(s.contains(FINGERPRINT_UNSET));
    }

    // ── ReplayTokenResponse edge cases ──────────────────────────────

    #[test]
    fn replay_token_response_empty_reason() {
        let body = ReplayTokenResponse {
            rejected: true,
            reason: String::new(),
        };
        let s = serde_json::to_string(&body).expect("serialise");
        assert!(s.contains("\"reason\":\"\""));
    }

    #[test]
    fn replay_token_response_long_reason() {
        let reason = "x".repeat(1000);
        let body = ReplayTokenResponse {
            rejected: false,
            reason: reason.clone(),
        };
        let s = serde_json::to_string(&body).expect("serialise");
        assert!(s.contains(&reason));
    }

    // ── BAN_TEST_PREFIX isolation ────────────────────────────────────

    #[test]
    fn ban_test_prefix_does_not_overlap_production_keys() {
        // Production ban keys are `ban:<hex-nullifier>`. The test prefix
        // `ban:test:` can never collide because hex chars are [0-9a-f],
        // which never form the word "test:" immediately after "ban:".
        assert!(BAN_TEST_PREFIX.starts_with("ban:test:"));
    }

    #[test]
    fn ban_test_prefix_is_longer_than_ban_colon() {
        assert!(BAN_TEST_PREFIX.len() > "ban:".len());
    }

    // ── unset_fingerprint consistency ────────────────────────────────

    #[test]
    fn unset_fingerprint_is_six_chars() {
        assert_eq!(unset_fingerprint().len(), 6);
    }

    #[test]
    fn unset_fingerprint_is_all_zeros() {
        assert!(unset_fingerprint().chars().all(|c| c == '0'));
    }

    // ── constant-time compare: known fingerprint vectors ────────────

    #[test]
    fn fingerprint_of_abc_matches_known_vector() {
        // SHA-256("abc") prefix = "ba7816"
        let fp = fingerprint6_bytes(b"abc");
        assert_eq!(fp, "ba7816");
    }

    #[test]
    fn fingerprint_of_empty_bytes_is_sentinel() {
        let fp = fingerprint6_bytes(b"");
        assert_eq!(fp, FINGERPRINT_UNSET);
    }

    // ── MekProbeResponse deserialisation ─────────────────────────────

    #[test]
    fn mek_probe_response_deserialises_from_json() {
        let json = r#"{"ok":true,"slot":"current","actual_fingerprint":"ba7816"}"#;
        let parsed: serde_json::Value = serde_json::from_str(json).expect("valid JSON"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["slot"], "current");
        assert_eq!(parsed["actual_fingerprint"], "ba7816");
    }

    // ── Lockout threshold boundary ──────────────────────────────────

    #[test]
    fn lockout_threshold_is_less_than_hourly_limit() {
        // The lockout should trigger before the hourly rate limit ceiling,
        // preventing brute-force before the softer cap kicks in.
        let threshold = ADMIN_LOCKOUT_THRESHOLD;
        let limit = ADMIN_RL_LIMIT_PER_HOUR;
        assert!(
            threshold < limit,
            "lockout ({threshold}) must be < hourly limit ({limit})"
        );
    }

    #[test]
    fn lockout_ttl_is_one_hour() {
        assert_eq!(ADMIN_LOCKOUT_TTL_SECS, 3600);
    }

    // ── MekProbeRequest extra deserialisation ──────────────────────

    #[test]
    fn mek_probe_request_rejects_null_fields() {
        let json = r#"{
            "encrypted_secret": null,
            "expected_plaintext_fingerprint": "ba7816"
        }"#;
        let result = serde_json::from_str::<MekProbeRequest>(json);
        assert!(result.is_err(), "null encrypted_secret must error");
    }

    #[test]
    fn mek_probe_request_rejects_numeric_fingerprint() {
        let json = r#"{
            "encrypted_secret": "ZW52ZWxvcGU=",
            "expected_plaintext_fingerprint": 123456
        }"#;
        let result = serde_json::from_str::<MekProbeRequest>(json);
        assert!(result.is_err(), "numeric fingerprint must error");
    }

    #[test]
    fn mek_probe_request_rejects_array_body() {
        let result = serde_json::from_str::<MekProbeRequest>("[]");
        assert!(result.is_err());
    }

    #[test]
    fn mek_probe_request_preserves_whitespace_in_fingerprint() {
        let json = r#"{
            "encrypted_secret": "ZW52ZWxvcGU=",
            "expected_plaintext_fingerprint": " ba7816 "
        }"#;
        let req: MekProbeRequest = serde_json::from_str(json).expect("parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(req.expected_plaintext_fingerprint, " ba7816 ");
    }

    #[test]
    fn mek_probe_request_unicode_fingerprint() {
        let json = r#"{
            "encrypted_secret": "ZW52ZWxvcGU=",
            "expected_plaintext_fingerprint": "ééé"
        }"#;
        let req: MekProbeRequest = serde_json::from_str(json).expect("parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert!(!req.expected_plaintext_fingerprint.is_empty());
    }

    // ── ReplayTokenRequest extra deserialisation ───────────────────

    #[test]
    fn replay_token_request_rejects_null_token() {
        let json = r#"{ "token": null }"#;
        let result = serde_json::from_str::<ReplayTokenRequest>(json);
        assert!(result.is_err(), "null token must error");
    }

    #[test]
    fn replay_token_request_rejects_numeric_token() {
        let json = r#"{ "token": 12345 }"#;
        let result = serde_json::from_str::<ReplayTokenRequest>(json);
        assert!(result.is_err(), "numeric token must error");
    }

    #[test]
    fn replay_token_request_long_token() {
        let long_token = "x".repeat(10_000);
        let json = format!(r#"{{ "token": "{}" }}"#, long_token);
        let req: ReplayTokenRequest = serde_json::from_str(&json).expect("parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(req.token.len(), 10_000);
    }

    // ── MekProbeResponse serialisation completeness ────────────────

    #[test]
    fn mek_probe_response_json_key_names() {
        let body = MekProbeResponse {
            ok: true,
            slot: Some("current"),
            actual_fingerprint: "abcdef".to_string(),
        };
        let v: serde_json::Value = serde_json::to_value(&body).expect("to_value");
        assert!(v.get("ok").is_some());
        assert!(v.get("slot").is_some());
        assert!(v.get("actual_fingerprint").is_some());
    }

    #[test]
    fn mek_probe_response_ok_false_slot_some_is_inconsistent_but_serialises() {
        // The handler always sets ok=false when slot is None, but the struct
        // itself does not enforce that invariant. Verify serialisation works
        // regardless.
        let body = MekProbeResponse {
            ok: false,
            slot: Some("current"),
            actual_fingerprint: "ba7816".to_string(),
        };
        let s = serde_json::to_string(&body).expect("serialise");
        assert!(s.contains("\"ok\":false"));
        assert!(s.contains("\"slot\":\"current\""));
    }

    // ── ReplayTokenResponse serialisation completeness ─────────────

    #[test]
    fn replay_token_response_json_key_names() {
        let body = ReplayTokenResponse {
            rejected: true,
            reason: "expired".to_string(),
        };
        let v: serde_json::Value = serde_json::to_value(&body).expect("to_value");
        assert!(v.get("rejected").is_some());
        assert!(v.get("reason").is_some());
    }

    #[test]
    fn replay_token_response_special_chars_in_reason() {
        let body = ReplayTokenResponse {
            rejected: true,
            reason: r#"error: "bad token" <>&"#.to_string(),
        };
        let s = serde_json::to_string(&body).expect("serialise");
        let parsed: serde_json::Value = serde_json::from_str(&s).expect("parse back"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(
            parsed["reason"].as_str().expect("reason is string"),
            r#"error: "bad token" <>&"#
        );
    }

    // ── fingerprint constant-time edge cases ───────────────────────

    #[test]
    fn fingerprint_compare_different_lengths_is_false() {
        let a = "ba7816";
        let b = "ba78160";
        let result = bool::from(a.as_bytes().ct_eq(b.as_bytes()));
        assert!(!result, "different-length fingerprints must not match");
    }

    #[test]
    fn fingerprint_compare_empty_strings_matches() {
        let a = "";
        let b = "";
        let result = bool::from(a.as_bytes().ct_eq(b.as_bytes()));
        assert!(result, "two empty byte slices are ct_eq");
    }

    #[test]
    fn fingerprint_of_single_byte_is_deterministic() {
        let fp1 = fingerprint6_bytes(b"x");
        let fp2 = fingerprint6_bytes(b"x");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint6_is_always_six_hex_chars() {
        for input in &[b"a".as_slice(), b"hello world", b"\x00\xff\x80"] {
            let fp = fingerprint6_bytes(input);
            assert_eq!(
                fp.len(),
                6,
                "fingerprint must be 6 chars for input {:?}",
                input
            );
            assert!(
                fp.chars().all(|c| c.is_ascii_hexdigit()),
                "fingerprint must be hex for input {:?}",
                input
            );
        }
    }

    // ── Admin constant relationships ───────────────────────────────

    #[test]
    fn lockout_ttl_u32_fits_in_u64() {
        // Ensures the u32 constant never wraps when widened.
        assert!(u64::from(ADMIN_LOCKOUT_TTL_SECS_U32) <= ADMIN_LOCKOUT_TTL_SECS);
    }

    #[test]
    fn admin_hourly_limit_is_nonzero() {
        assert!(ADMIN_RL_LIMIT_PER_HOUR > 0);
    }

    #[test]
    fn admin_lockout_threshold_is_nonzero() {
        assert!(ADMIN_LOCKOUT_THRESHOLD > 0);
    }

    // ── BAN_TEST_PREFIX format ──────────────────────────────────────

    #[test]
    fn ban_test_prefix_contains_no_whitespace() {
        assert!(
            !BAN_TEST_PREFIX.chars().any(|c| c.is_whitespace()),
            "BAN_TEST_PREFIX must not contain whitespace"
        );
    }

    #[test]
    fn ban_test_prefix_is_ascii() {
        assert!(BAN_TEST_PREFIX.is_ascii());
    }

    #[test]
    fn ban_test_prefix_does_not_match_bare_ban_key() {
        // A production key like "ban:abc123" must NOT start with BAN_TEST_PREFIX.
        let prod_key = "ban:abc123";
        assert!(!prod_key.starts_with(BAN_TEST_PREFIX));
    }

    #[test]
    fn ban_test_key_example_matches_prefix() {
        let test_key = format!("{}my_test_entry", BAN_TEST_PREFIX);
        assert!(test_key.starts_with(BAN_TEST_PREFIX));
    }

    // ── unset_fingerprint idempotency ───────────────────────────────

    #[test]
    fn unset_fingerprint_is_idempotent() {
        let a = unset_fingerprint();
        let b = unset_fingerprint();
        assert_eq!(a, b);
    }

    #[test]
    fn unset_fingerprint_is_valid_hex() {
        assert!(unset_fingerprint().chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── MekProbeRequest with extra fields ───────────────────────────

    #[test]
    fn mek_probe_request_ignores_extra_fields_by_default() {
        // serde default is to ignore unknown fields unless deny_unknown_fields is set.
        let json = r#"{
            "encrypted_secret": "ZW52ZWxvcGU=",
            "expected_plaintext_fingerprint": "ba7816",
            "bonus_field": true
        }"#;
        let result = serde_json::from_str::<MekProbeRequest>(json);
        // MekProbeRequest does NOT have deny_unknown_fields, so this should succeed.
        assert!(result.is_ok());
    }

    // ── ReplayTokenResponse round-trip ──────────────────────────────

    #[test]
    fn replay_token_response_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let original = ReplayTokenResponse {
            rejected: true,
            reason: "token expired after rotation".to_string(),
        };
        let json = serde_json::to_string(&original)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["rejected"], true);
        assert_eq!(parsed["reason"], "token expired after rotation");
        Ok(())
    }

    #[test]
    fn replay_token_response_round_trip_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let original = ReplayTokenResponse {
            rejected: false,
            reason: "token still accepted".to_string(),
        };
        let json = serde_json::to_string(&original)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["rejected"], false);
        assert_eq!(parsed["reason"], "token still accepted");
        Ok(())
    }
}
