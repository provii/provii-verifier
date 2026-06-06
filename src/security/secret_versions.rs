// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Per-request `secret_version` log + `x-secret-version` HTTP response header
//! emission for rotation-capable secrets.
//!
//! Per the rotation specification: the
//! Grafana panel queries the JSON-extracted log field and the per-Worker
//! rotation tests assert the response header. Both surfaces carry the same
//! 6-character hex fingerprint of the secret value, computed once at startup
//! by `super::secret_fingerprint::fingerprint6_str`.
//!
//! The schema is a JSON object keyed by role-suffix (e.g. `VERIFIER_MEK_PROD`,
//! `VERIFIER_HMAC_PROD`, `SESSION_TOKEN_PROD`, `IP_HASH_SALT_PROD`). The
//! role-suffix tracks both the secret and the deployment environment so
//! sandbox traffic does not collide with production fingerprints in the panel
//! grouping.
//!
//! Handlers that touch a single rotation-capable secret call
//! [`SecretVersionLine::single`] to build the log line + header value. Handlers
//! that touch multiple secrets in one request build a [`SecretVersionLine`]
//! incrementally and emit it once before responding.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use worker::{Error as WorkerError, Response};

use super::secret_fingerprint::FINGERPRINT_UNSET;

#[cfg(target_arch = "wasm32")]
use worker::console_log;

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_macros)]
macro_rules! console_log {
    ($($t:tt)*) => {{}};
}

/// Role-suffix labels for provii-verifier rotation-capable secrets. The `_PROD`
/// vs `_SBX` discriminator follows the pattern established by
/// [`super::status_auth::status_token_role_for_env`]: anything other than
/// `"sandbox"` or `"development"` lands on `_PROD` so misconfigured deployments
/// fail closed onto the production-label dashboard.
#[must_use]
pub fn mek_role_for_env(environment: &str) -> &'static str {
    match environment {
        "sandbox" | "development" => "VERIFIER_MEK_SBX",
        _ => "VERIFIER_MEK_PROD",
    }
}

/// Role-suffix label for `HOSTED_MEK`. Same env-aware mapping as
/// [`mek_role_for_env`].
#[must_use]
pub fn hosted_mek_role_for_env(environment: &str) -> &'static str {
    match environment {
        "sandbox" | "development" => "HOSTED_MEK_SBX",
        _ => "HOSTED_MEK_PROD",
    }
}

/// Role-suffix label for `VERIFIER_HMAC` (per-client encrypted HMAC secret
/// envelope). The HMAC secret rotates via MEK rotation in the current
/// architecture, but the panel emits a separate label so the analyst can see
/// HMAC-class traffic independently of the MEK-class load.
#[must_use]
pub fn verifier_hmac_role_for_env(environment: &str) -> &'static str {
    match environment {
        "sandbox" | "development" => "VERIFIER_HMAC_SBX",
        _ => "VERIFIER_HMAC_PROD",
    }
}

/// Role-suffix label for `SESSION_TOKEN_SECRET`.
#[must_use]
pub fn session_token_role_for_env(environment: &str) -> &'static str {
    match environment {
        "sandbox" | "development" => "SESSION_TOKEN_SBX",
        _ => "SESSION_TOKEN_PROD",
    }
}

/// Role-suffix label for `VERIFIER_IP_HASH_SALT`.
#[must_use]
pub fn ip_hash_salt_role_for_env(environment: &str) -> &'static str {
    match environment {
        "sandbox" | "development" => "IP_HASH_SALT_SBX",
        _ => "IP_HASH_SALT_PROD",
    }
}

/// Slot identifier surfaced by rotation-aware primitives so callers can
/// attribute the satisfying slot on the per-request `secret_version` log
/// line. Mirrors the harness `Slot` type used by the rotation tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationSlot {
    /// Current (primary) slot satisfied the verify path.
    Current,
    /// Previous slot satisfied the verify path. Carries the rotation-window
    /// signal: any non-zero rate of `Previous` after the runbook says the slot
    /// has been dropped indicates a stale caller.
    Previous,
}

impl RotationSlot {
    /// Resolve to the role-suffix label used in `secret_version_used`.
    /// Returns `role` for [`Self::Current`] and `format!("{role}_PREVIOUS")`
    /// for [`Self::Previous`].
    #[must_use]
    pub fn used_label(self, role: &str) -> String {
        match self {
            Self::Current => role.to_string(),
            Self::Previous => format!("{role}_PREVIOUS"),
        }
    }
}

/// Builds the `secret_version` JSON object + the matching `x-secret-version`
/// response header value for a single request.
///
/// Per the structured log schema:
///
/// ```json
/// {
///   "secret_version": { "<ROLE>": "<6hex>", "<ROLE>_PREVIOUS": "<6hex>" },
///   "secret_version_used": "<ROLE>" | "<ROLE>_PREVIOUS"
/// }
/// ```
///
/// The header carries the 6-char fingerprint of the slot that satisfied the
/// request (the same value as `secret_version_used` resolved against the map).
#[derive(Debug, Clone)]
pub struct SecretVersionLine {
    versions: BTreeMap<String, String>,
    used: Option<String>,
    used_role: Option<String>,
}

impl Default for SecretVersionLine {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretVersionLine {
    /// Construct an empty line. Add slots via [`Self::add_slot`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            versions: BTreeMap::new(),
            used: None,
            used_role: None,
        }
    }

    /// Convenience constructor for the common case: a handler that touches a
    /// single rotation-capable secret with current + previous slot
    /// fingerprints. `used_role` MUST be one of `role` or `format!("{role}_PREVIOUS")`
    /// or [`None`] when the verify path did not reach this secret (e.g. an
    /// auth-rejected request).
    #[must_use]
    pub fn single(
        role: &str,
        current_fingerprint: &str,
        previous_fingerprint: &str,
        used_role: Option<&str>,
    ) -> Self {
        let mut line = Self::new();
        line.add_slot(role, current_fingerprint, previous_fingerprint);
        if let Some(u) = used_role {
            line.set_used(u);
        }
        line
    }

    /// Convenience constructor that takes a [`RotationSlot`] directly. Equivalent
    /// to [`Self::single`] with the `used_role` resolved via
    /// [`RotationSlot::used_label`].
    #[must_use]
    pub fn single_for_slot(
        role: &str,
        current_fingerprint: &str,
        previous_fingerprint: &str,
        used: Option<RotationSlot>,
    ) -> Self {
        let used_label = used.map(|s| s.used_label(role));
        Self::single(
            role,
            current_fingerprint,
            previous_fingerprint,
            used_label.as_deref(),
        )
    }

    /// Add a slot keyed by [`RotationSlot`] and mark it as used in one call.
    /// Useful when a handler needs to record multiple secrets in a single line.
    pub fn add_slot_used(
        &mut self,
        role: &str,
        current_fingerprint: &str,
        previous_fingerprint: &str,
        used: Option<RotationSlot>,
    ) -> &mut Self {
        self.add_slot(role, current_fingerprint, previous_fingerprint);
        if let Some(slot) = used {
            let label = slot.used_label(role);
            self.set_used(&label);
        }
        self
    }

    /// Record the current + previous fingerprint for a given role-suffix.
    /// Subsequent calls with the same role overwrite. The previous slot value
    /// of [`FINGERPRINT_UNSET`] (`"000000"`) signals "no value bound", which
    /// is the steady state outside a rotation window.
    pub fn add_slot(
        &mut self,
        role: &str,
        current_fingerprint: &str,
        previous_fingerprint: &str,
    ) -> &mut Self {
        self.versions
            .insert(role.to_string(), current_fingerprint.to_string());
        self.versions
            .insert(format!("{role}_PREVIOUS"), previous_fingerprint.to_string());
        self
    }

    /// Mark which slot satisfied the verify path. Must match a key already
    /// added via [`Self::add_slot`] (either `role` or `role_PREVIOUS`). The
    /// fingerprint of that slot becomes the `x-secret-version` header value.
    pub fn set_used(&mut self, used_role: &str) -> &mut Self {
        self.used_role = Some(used_role.to_string());
        self.used = self.versions.get(used_role).cloned();
        self
    }

    /// Resolve the 6-char fingerprint of the satisfying slot, or
    /// [`FINGERPRINT_UNSET`] when no slot was used.
    #[must_use]
    pub fn header_value(&self) -> &str {
        self.used.as_deref().unwrap_or(FINGERPRINT_UNSET)
    }

    /// JSON object body for the `secret_version` log field. Sorted keys come
    /// from the underlying [`BTreeMap`] so the encoded bytes are deterministic
    /// across runs (helps log diffing).
    #[must_use]
    pub fn versions_json(&self) -> String {
        let mut out = String::from("{");
        let mut first = true;
        for (k, v) in &self.versions {
            if !first {
                out.push(',');
            }
            first = false;
            // Keys are role-suffix labels (ASCII identifiers, no escaping needed).
            // Values are 6-char hex fingerprints (ASCII hex). Both are safe to
            // embed directly without JSON escaping.
            out.push('"');
            out.push_str(k);
            out.push_str("\":\"");
            out.push_str(v);
            out.push('"');
        }
        out.push('}');
        out
    }

    /// Emit the structured log line. Caller passes the `route` label that the
    /// Grafana panel groups by. The log shape matches the structured schema so
    /// the same LogQL queries cover both `STATUS_TOKEN` and the wider
    /// secret set.
    pub fn emit_log(&self, _route: &str) {
        let _used_label = self.used_role.as_deref().unwrap_or("none");
        #[cfg(target_arch = "wasm32")]
        console_log!(
            r#"{{"event":"secret_version","route":"{}","secret_version":{},"secret_version_used":"{}"}}"#,
            _route,
            self.versions_json(),
            _used_label
        );
    }

    /// Apply the `x-secret-version` HTTP response header to a [`Response`]
    /// before it is returned to the caller. The header value is the fingerprint
    /// of the slot that satisfied the verify path, or [`FINGERPRINT_UNSET`]
    /// when no rotation-capable verify happened.
    ///
    /// Per the rotation specification the header surface is what the test harness asserts; the
    /// log field is what the panel queries. Both must carry the same value.
    pub fn apply_header(&self, response: &mut Response) -> Result<(), WorkerError> {
        response
            .headers_mut()
            .set("x-secret-version", self.header_value())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::string_slice)]
mod tests {
    use super::*;

    #[test]
    fn role_suffix_production_yields_prod() {
        assert_eq!(mek_role_for_env("production"), "VERIFIER_MEK_PROD");
        assert_eq!(hosted_mek_role_for_env("production"), "HOSTED_MEK_PROD");
        assert_eq!(
            verifier_hmac_role_for_env("production"),
            "VERIFIER_HMAC_PROD"
        );
        assert_eq!(
            session_token_role_for_env("production"),
            "SESSION_TOKEN_PROD"
        );
        assert_eq!(ip_hash_salt_role_for_env("production"), "IP_HASH_SALT_PROD");
    }

    #[test]
    fn role_suffix_sandbox_yields_sbx() {
        assert_eq!(mek_role_for_env("sandbox"), "VERIFIER_MEK_SBX");
        assert_eq!(hosted_mek_role_for_env("sandbox"), "HOSTED_MEK_SBX");
        assert_eq!(verifier_hmac_role_for_env("sandbox"), "VERIFIER_HMAC_SBX");
        assert_eq!(session_token_role_for_env("sandbox"), "SESSION_TOKEN_SBX");
        assert_eq!(ip_hash_salt_role_for_env("sandbox"), "IP_HASH_SALT_SBX");
    }

    #[test]
    fn role_suffix_unknown_env_falls_back_to_prod() {
        assert_eq!(mek_role_for_env(""), "VERIFIER_MEK_PROD");
        assert_eq!(mek_role_for_env("test"), "VERIFIER_MEK_PROD");
        assert_eq!(mek_role_for_env("staging"), "VERIFIER_MEK_PROD");
    }

    #[test]
    fn single_slot_with_current_used() {
        let line = SecretVersionLine::single(
            "VERIFIER_MEK_PROD",
            "abcdef",
            "000000",
            Some("VERIFIER_MEK_PROD"),
        );
        assert_eq!(line.header_value(), "abcdef");
        let json = line.versions_json();
        assert!(json.contains(r#""VERIFIER_MEK_PROD":"abcdef""#));
        assert!(json.contains(r#""VERIFIER_MEK_PROD_PREVIOUS":"000000""#));
    }

    #[test]
    fn single_slot_with_previous_used() {
        let line = SecretVersionLine::single(
            "VERIFIER_MEK_PROD",
            "abcdef",
            "fedcba",
            Some("VERIFIER_MEK_PROD_PREVIOUS"),
        );
        assert_eq!(line.header_value(), "fedcba");
    }

    #[test]
    fn unused_slot_yields_unset_header() {
        let line = SecretVersionLine::single("VERIFIER_MEK_PROD", "abcdef", "000000", None);
        assert_eq!(line.header_value(), FINGERPRINT_UNSET);
    }

    #[test]
    fn multiple_slots_serialise_sorted() {
        let mut line = SecretVersionLine::new();
        line.add_slot("VERIFIER_MEK_PROD", "111111", "000000");
        line.add_slot("VERIFIER_HMAC_PROD", "222222", "000000");
        line.set_used("VERIFIER_MEK_PROD");
        let json = line.versions_json();
        // BTreeMap preserves sorted order: HMAC < MEK lexicographically.
        let hmac_pos = json.find("VERIFIER_HMAC_PROD").expect("has HMAC role");
        let mek_pos = json.find("VERIFIER_MEK_PROD").expect("has MEK role");
        assert!(hmac_pos < mek_pos);
        assert_eq!(line.header_value(), "111111");
    }

    #[test]
    fn versions_json_is_valid_json_object() {
        let line = SecretVersionLine::single(
            "VERIFIER_MEK_PROD",
            "abcdef",
            "000000",
            Some("VERIFIER_MEK_PROD"),
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&line.versions_json()) // nosemgrep: provii.workers.expect-on-external-input
                .expect("versions_json must round-trip through serde_json");
        assert!(parsed.is_object());
    }

    #[test]
    fn empty_line_yields_unset_header_and_empty_object() {
        let line = SecretVersionLine::new();
        assert_eq!(line.header_value(), FINGERPRINT_UNSET);
        assert_eq!(line.versions_json(), "{}");
    }

    #[test]
    fn rotation_slot_resolves_to_label() {
        assert_eq!(
            RotationSlot::Current.used_label("VERIFIER_MEK_PROD"),
            "VERIFIER_MEK_PROD"
        );
        assert_eq!(
            RotationSlot::Previous.used_label("VERIFIER_MEK_PROD"),
            "VERIFIER_MEK_PROD_PREVIOUS"
        );
    }

    /// Per-secret-class log-shape assertions: each rotation-capable secret has
    /// its own role-suffix label, and the satisfying-slot signal must resolve
    /// to either `<ROLE>` or `<ROLE>_PREVIOUS` in `secret_version_used`. These
    /// mirror the harness `secret_version_log` shape used by the rotation
    /// tests so any regression here surfaces in both the host-side test and
    /// the production emit.
    #[test]
    fn line_for_slot_verifier_mek_current() {
        let line = SecretVersionLine::single_for_slot(
            "VERIFIER_MEK_PROD",
            "aaaaaa",
            "000000",
            Some(RotationSlot::Current),
        );
        let json = line.versions_json();
        assert!(json.contains(r#""VERIFIER_MEK_PROD":"aaaaaa""#));
        assert!(json.contains(r#""VERIFIER_MEK_PROD_PREVIOUS":"000000""#));
        assert_eq!(line.header_value(), "aaaaaa");
    }

    #[test]
    fn line_for_slot_verifier_mek_previous() {
        let line = SecretVersionLine::single_for_slot(
            "VERIFIER_MEK_PROD",
            "aaaaaa",
            "bbbbbb",
            Some(RotationSlot::Previous),
        );
        assert_eq!(line.header_value(), "bbbbbb");
    }

    #[test]
    fn line_for_slot_session_token_current() {
        let line = SecretVersionLine::single_for_slot(
            "SESSION_TOKEN_PROD",
            "111111",
            "000000",
            Some(RotationSlot::Current),
        );
        assert!(line
            .versions_json()
            .contains(r#""SESSION_TOKEN_PROD":"111111""#));
        assert_eq!(line.header_value(), "111111");
    }

    #[test]
    fn line_for_slot_hosted_mek_previous() {
        let line = SecretVersionLine::single_for_slot(
            "HOSTED_MEK_PROD",
            "deadbe",
            "ef0123",
            Some(RotationSlot::Previous),
        );
        assert_eq!(line.header_value(), "ef0123");
    }

    #[test]
    fn line_for_slot_status_token_current() {
        let line = SecretVersionLine::single_for_slot(
            "STATUS_TOKEN_PROD",
            "424242",
            "000000",
            Some(RotationSlot::Current),
        );
        assert!(line
            .versions_json()
            .contains(r#""STATUS_TOKEN_PROD":"424242""#));
        assert_eq!(line.header_value(), "424242");
    }

    #[test]
    fn line_for_slot_ip_hash_salt_no_used() {
        // IP_HASH_SALT ships single-hash mode; used is None so
        // the header carries the unset sentinel.
        let line =
            SecretVersionLine::single_for_slot("IP_HASH_SALT_PROD", "112233", "000000", None);
        assert!(line
            .versions_json()
            .contains(r#""IP_HASH_SALT_PROD":"112233""#));
        assert!(line
            .versions_json()
            .contains(r#""IP_HASH_SALT_PROD_PREVIOUS":"000000""#));
        assert_eq!(line.header_value(), FINGERPRINT_UNSET);
    }

    #[test]
    fn add_slot_used_records_label_and_header() {
        let mut line = SecretVersionLine::new();
        line.add_slot_used(
            "VERIFIER_MEK_PROD",
            "abcdef",
            "fedcba",
            Some(RotationSlot::Previous),
        );
        line.add_slot("IP_HASH_SALT_PROD", "112233", "000000");
        // Header must carry the MEK previous slot fingerprint, not the
        // IP_HASH_SALT current fingerprint, because only MEK was marked used.
        assert_eq!(line.header_value(), "fedcba");
        let json = line.versions_json();
        assert!(json.contains(r#""IP_HASH_SALT_PROD":"112233""#));
        assert!(json.contains(r#""VERIFIER_MEK_PROD_PREVIOUS":"fedcba""#));
    }

    // ── Role-suffix: development environment ──────────────────────────

    #[test]
    fn role_suffix_development_yields_sbx() {
        assert_eq!(mek_role_for_env("development"), "VERIFIER_MEK_SBX");
        assert_eq!(hosted_mek_role_for_env("development"), "HOSTED_MEK_SBX");
        assert_eq!(
            verifier_hmac_role_for_env("development"),
            "VERIFIER_HMAC_SBX"
        );
        assert_eq!(
            session_token_role_for_env("development"),
            "SESSION_TOKEN_SBX"
        );
        assert_eq!(ip_hash_salt_role_for_env("development"), "IP_HASH_SALT_SBX");
    }

    #[test]
    fn role_suffix_empty_string_falls_back_to_prod_all_functions() {
        assert_eq!(hosted_mek_role_for_env(""), "HOSTED_MEK_PROD");
        assert_eq!(verifier_hmac_role_for_env(""), "VERIFIER_HMAC_PROD");
        assert_eq!(session_token_role_for_env(""), "SESSION_TOKEN_PROD");
        assert_eq!(ip_hash_salt_role_for_env(""), "IP_HASH_SALT_PROD");
    }

    #[test]
    fn role_suffix_mixed_case_falls_back_to_prod() {
        // Case-sensitive matching: "Sandbox" != "sandbox".
        assert_eq!(mek_role_for_env("Sandbox"), "VERIFIER_MEK_PROD");
        assert_eq!(mek_role_for_env("PRODUCTION"), "VERIFIER_MEK_PROD");
        assert_eq!(mek_role_for_env("Development"), "VERIFIER_MEK_PROD");
    }

    // ── RotationSlot enum tests ───────────────────────────────────────

    #[test]
    fn rotation_slot_debug_format() {
        assert_eq!(format!("{:?}", RotationSlot::Current), "Current");
        assert_eq!(format!("{:?}", RotationSlot::Previous), "Previous");
    }

    #[test]
    fn rotation_slot_clone() {
        let slot = RotationSlot::Current;
        let cloned = slot;
        assert_eq!(slot, cloned);
    }

    #[test]
    fn rotation_slot_eq() {
        assert_eq!(RotationSlot::Current, RotationSlot::Current);
        assert_eq!(RotationSlot::Previous, RotationSlot::Previous);
        assert_ne!(RotationSlot::Current, RotationSlot::Previous);
    }

    #[test]
    fn rotation_slot_used_label_with_empty_role() {
        assert_eq!(RotationSlot::Current.used_label(""), "");
        assert_eq!(RotationSlot::Previous.used_label(""), "_PREVIOUS");
    }

    // ── SecretVersionLine: new() and Default ──────────────────────────

    #[test]
    fn new_and_default_are_equivalent() {
        let from_new = SecretVersionLine::new();
        let from_default = SecretVersionLine::default();
        assert_eq!(from_new.header_value(), from_default.header_value());
        assert_eq!(from_new.versions_json(), from_default.versions_json());
    }

    #[test]
    fn default_debug_format() {
        let line = SecretVersionLine::default();
        let debug = format!("{:?}", line);
        assert!(debug.contains("SecretVersionLine"));
    }

    // ── SecretVersionLine: add_slot chaining ──────────────────────────

    #[test]
    fn add_slot_returns_self_for_chaining() {
        let mut line = SecretVersionLine::new();
        line.add_slot("ROLE_A", "aaaaaa", "000000")
            .add_slot("ROLE_B", "bbbbbb", "000000");
        let json = line.versions_json();
        assert!(json.contains("ROLE_A"));
        assert!(json.contains("ROLE_B"));
    }

    #[test]
    fn add_slot_overwrites_same_role() {
        let mut line = SecretVersionLine::new();
        line.add_slot("ROLE_A", "111111", "000000");
        line.add_slot("ROLE_A", "222222", "333333");
        let json = line.versions_json();
        assert!(json.contains(r#""ROLE_A":"222222""#));
        assert!(json.contains(r#""ROLE_A_PREVIOUS":"333333""#));
        // Old values should be gone.
        assert!(!json.contains("111111"));
    }

    // ── SecretVersionLine: set_used with nonexistent role ─────────────

    #[test]
    fn set_used_nonexistent_role_yields_unset_header() {
        let mut line = SecretVersionLine::new();
        line.add_slot("ROLE_A", "aaaaaa", "000000");
        line.set_used("NONEXISTENT_ROLE");
        // used is None because versions.get("NONEXISTENT_ROLE") returns None.
        assert_eq!(line.header_value(), FINGERPRINT_UNSET);
    }

    // ── SecretVersionLine: set_used overwrites previous ───────────────

    #[test]
    fn set_used_can_change_used_role() {
        let mut line = SecretVersionLine::new();
        line.add_slot("ROLE_A", "aaaaaa", "bbbbbb");
        line.set_used("ROLE_A");
        assert_eq!(line.header_value(), "aaaaaa");
        line.set_used("ROLE_A_PREVIOUS");
        assert_eq!(line.header_value(), "bbbbbb");
    }

    // ── SecretVersionLine: single_for_slot with None ──────────────────

    #[test]
    fn single_for_slot_none_used() {
        let line = SecretVersionLine::single_for_slot("ROLE_A", "aaaaaa", "000000", None);
        assert_eq!(line.header_value(), FINGERPRINT_UNSET);
        let json = line.versions_json();
        assert!(json.contains(r#""ROLE_A":"aaaaaa""#));
        assert!(json.contains(r#""ROLE_A_PREVIOUS":"000000""#));
    }

    // ── SecretVersionLine: add_slot_used with None slot ───────────────

    #[test]
    fn add_slot_used_with_none_does_not_override_existing_used() {
        let mut line = SecretVersionLine::new();
        line.add_slot("ROLE_A", "aaaaaa", "000000");
        line.set_used("ROLE_A");
        assert_eq!(line.header_value(), "aaaaaa");
        // add_slot_used with None should not change the used role.
        line.add_slot_used("ROLE_B", "bbbbbb", "000000", None);
        assert_eq!(line.header_value(), "aaaaaa");
    }

    #[test]
    fn add_slot_used_with_current_overrides_previous_used() {
        let mut line = SecretVersionLine::new();
        line.add_slot_used("ROLE_A", "aaaaaa", "000000", Some(RotationSlot::Current));
        assert_eq!(line.header_value(), "aaaaaa");
        line.add_slot_used("ROLE_B", "bbbbbb", "cccccc", Some(RotationSlot::Previous));
        // Now ROLE_B_PREVIOUS is used.
        assert_eq!(line.header_value(), "cccccc");
    }

    // ── versions_json: deterministic ordering ─────────────────────────

    #[test]
    fn versions_json_alphabetical_ordering() {
        let mut line = SecretVersionLine::new();
        // Add in reverse alphabetical order.
        line.add_slot("Z_ROLE", "zzzzzz", "000000");
        line.add_slot("A_ROLE", "aaaaaa", "000000");
        line.add_slot("M_ROLE", "mmmmmm", "000000");
        let json = line.versions_json();
        let a_pos = json.find("A_ROLE").expect("has A_ROLE");
        let m_pos = json.find("M_ROLE").expect("has M_ROLE");
        let z_pos = json.find("Z_ROLE").expect("has Z_ROLE");
        assert!(a_pos < m_pos);
        assert!(m_pos < z_pos);
    }

    #[test]
    fn versions_json_single_slot_has_two_keys() {
        let line = SecretVersionLine::single("ROLE", "abcdef", "000000", None);
        let parsed: serde_json::Value =
            serde_json::from_str(&line.versions_json()).expect("valid JSON"); // nosemgrep: provii.workers.expect-on-external-input
        let obj = parsed.as_object().expect("object");
        assert_eq!(obj.len(), 2);
        assert!(obj.contains_key("ROLE"));
        assert!(obj.contains_key("ROLE_PREVIOUS"));
    }

    // ── emit_log: smoke test (no panic) ───────────────────────────────

    #[test]
    fn emit_log_empty_line_does_not_panic() {
        let line = SecretVersionLine::new();
        line.emit_log("test_route");
    }

    #[test]
    fn emit_log_populated_line_does_not_panic() {
        let line = SecretVersionLine::single(
            "VERIFIER_MEK_PROD",
            "abcdef",
            "000000",
            Some("VERIFIER_MEK_PROD"),
        );
        line.emit_log("/v1/verify");
    }

    #[test]
    fn emit_log_with_no_used_does_not_panic() {
        let mut line = SecretVersionLine::new();
        line.add_slot("ROLE_A", "aaaaaa", "bbbbbb");
        line.emit_log("some_route");
    }

    // ── Clone trait ───────────────────────────────────────────────────

    #[test]
    fn secret_version_line_clone() {
        let original = SecretVersionLine::single("ROLE", "abcdef", "fedcba", Some("ROLE"));
        let cloned = original.clone();
        assert_eq!(cloned.header_value(), original.header_value());
        assert_eq!(cloned.versions_json(), original.versions_json());
    }

    // ── All role functions are consistent ──────────────────────────────

    #[test]
    fn all_prod_roles_end_with_prod() {
        let roles = vec![
            mek_role_for_env("production"),
            hosted_mek_role_for_env("production"),
            verifier_hmac_role_for_env("production"),
            session_token_role_for_env("production"),
            ip_hash_salt_role_for_env("production"),
        ];
        for role in &roles {
            assert!(
                role.ends_with("_PROD"),
                "production role '{}' must end with _PROD",
                role
            );
        }
    }

    #[test]
    fn all_sbx_roles_end_with_sbx() {
        let roles = vec![
            mek_role_for_env("sandbox"),
            hosted_mek_role_for_env("sandbox"),
            verifier_hmac_role_for_env("sandbox"),
            session_token_role_for_env("sandbox"),
            ip_hash_salt_role_for_env("sandbox"),
        ];
        for role in &roles {
            assert!(
                role.ends_with("_SBX"),
                "sandbox role '{}' must end with _SBX",
                role
            );
        }
    }

    #[test]
    fn prod_and_sbx_roles_are_distinct() {
        assert_ne!(mek_role_for_env("production"), mek_role_for_env("sandbox"));
        assert_ne!(
            hosted_mek_role_for_env("production"),
            hosted_mek_role_for_env("sandbox")
        );
        assert_ne!(
            verifier_hmac_role_for_env("production"),
            verifier_hmac_role_for_env("sandbox")
        );
        assert_ne!(
            session_token_role_for_env("production"),
            session_token_role_for_env("sandbox")
        );
        assert_ne!(
            ip_hash_salt_role_for_env("production"),
            ip_hash_salt_role_for_env("sandbox")
        );
    }

    #[test]
    fn single_for_slot_previous_populates_json_and_header() {
        let line = SecretVersionLine::single_for_slot(
            "VERIFIER_HMAC_PROD",
            "aaa111",
            "bbb222",
            Some(RotationSlot::Previous),
        );
        let json = line.versions_json();
        assert!(json.contains(r#""VERIFIER_HMAC_PROD":"aaa111""#));
        assert!(json.contains(r#""VERIFIER_HMAC_PROD_PREVIOUS":"bbb222""#));
        assert_eq!(line.header_value(), "bbb222");
    }

    #[test]
    fn single_for_slot_current_resolves_header_to_current_fingerprint() {
        let line = SecretVersionLine::single_for_slot(
            "SESSION_TOKEN_SBX",
            "cccccc",
            "dddddd",
            Some(RotationSlot::Current),
        );
        assert_eq!(line.header_value(), "cccccc");
    }

    #[test]
    fn emit_log_after_multiple_add_slot_used_does_not_panic() {
        let mut line = SecretVersionLine::new();
        line.add_slot_used(
            "VERIFIER_MEK_PROD",
            "111111",
            "222222",
            Some(RotationSlot::Current),
        );
        line.add_slot_used(
            "VERIFIER_HMAC_PROD",
            "333333",
            "444444",
            Some(RotationSlot::Previous),
        );
        line.add_slot_used("IP_HASH_SALT_PROD", "555555", "000000", None);
        line.emit_log("/v1/verify");
    }

    #[test]
    fn emit_log_after_set_used_to_previous_does_not_panic() {
        let mut line = SecretVersionLine::new();
        line.add_slot("VERIFIER_MEK_PROD", "abcdef", "fedcba");
        line.set_used("VERIFIER_MEK_PROD_PREVIOUS");
        assert_eq!(line.header_value(), "fedcba");
        line.emit_log("/v1/session");
    }
}
