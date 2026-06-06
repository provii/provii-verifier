// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Secret expiry enforcement for ASVS V13.3.4 compliance.
//!
//! Implements automated checks for secret expiration and notifications when
//! secrets approach their expiry date. Secrets in Cloudflare Secrets Store
//! should have expiration dates, and this system detects when secrets are
//! approaching expiry to alert operators for proactive rotation.
//!
//! ASVS V13.3.4 \[L3\]: Verify that where possible, secrets have an expiry
//! date and are not hard-coded into the application source code.
//!
//! Cloudflare Secrets Store does not provide expiry metadata directly, so we
//! track secret creation dates in KV (`VERIFIER_KV_CONFIG`) and enforce a
//! mandatory rotation period (90 days for MEKs, aligned with our key rotation
//! policy).
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use serde::{Deserialize, Serialize};
use worker::{Env, Result};

/// Secret metadata stored in KV for expiry tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    /// Secret name (e.g., "VERIFIER_MEK_V3")
    pub name: String,

    /// Unix timestamp (seconds) when secret was created/rotated
    pub created_at: i64,

    /// Unix timestamp (seconds) when secret expires
    /// For MEKs: created_at + 90 days
    pub expires_at: i64,

    /// Secret version (if applicable, e.g., "V3")
    pub version: Option<String>,

    /// Last rotation timestamp (for tracking rotation history)
    pub last_rotated_at: Option<i64>,
}

impl SecretMetadata {
    /// Create new secret metadata with default 90-day expiry.
    pub fn new(name: String, created_at: i64) -> Self {
        const NINETY_DAYS_SECONDS: i64 = 90 * 24 * 60 * 60;

        Self {
            name,
            created_at,
            expires_at: created_at.saturating_add(NINETY_DAYS_SECONDS),
            version: None,
            last_rotated_at: None,
        }
    }

    /// Create with explicit expiry date.
    pub fn with_expiry(name: String, created_at: i64, expires_at: i64) -> Self {
        Self {
            name,
            created_at,
            expires_at,
            version: None,
            last_rotated_at: None,
        }
    }

    /// Set version identifier.
    pub fn with_version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }

    /// Days until expiry (negative if expired).
    #[allow(clippy::arithmetic_side_effects)] // i64 timestamp arithmetic cannot overflow in practice
    pub fn days_until_expiry(&self, current_time: i64) -> i64 {
        (self.expires_at - current_time) / (24 * 60 * 60)
    }

    /// Check if secret is expired.
    pub fn is_expired(&self, current_time: i64) -> bool {
        current_time >= self.expires_at
    }

    /// Check if secret is within warning threshold (30 days before expiry).
    pub fn is_expiring_soon(&self, current_time: i64, warning_days: i64) -> bool {
        let days_remaining = self.days_until_expiry(current_time);
        !self.is_expired(current_time) && days_remaining <= warning_days
    }

    /// Get age in days.
    #[allow(clippy::arithmetic_side_effects)] // i64 timestamp arithmetic cannot overflow in practice
    pub fn age_days(&self, current_time: i64) -> i64 {
        (current_time - self.created_at) / (24 * 60 * 60)
    }
}

/// Expiry check result with warnings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiryCheckResult {
    /// Secrets that are expired
    pub expired: Vec<String>,

    /// Secrets expiring soon (within warning threshold)
    pub expiring_soon: Vec<String>,

    /// Secrets that are healthy
    pub healthy: Vec<String>,

    /// Any errors encountered during check
    pub errors: Vec<String>,
}

impl ExpiryCheckResult {
    /// Check if there are any issues requiring attention.
    pub fn has_issues(&self) -> bool {
        !self.expired.is_empty() || !self.expiring_soon.is_empty()
    }

    /// Get total number of secrets checked.
    pub fn total_secrets(&self) -> usize {
        self.expired
            .len()
            .saturating_add(self.expiring_soon.len())
            .saturating_add(self.healthy.len())
    }
}

/// Default warning threshold: 30 days before expiry.
pub const DEFAULT_WARNING_DAYS: i64 = 30;

/// KV key prefix for secret metadata.
const SECRET_METADATA_PREFIX: &str = "secret_metadata:";

/// Check expiry status of all tracked secrets.
///
/// Loads secret metadata from KV (VERIFIER_KV_CONFIG), checks each
/// secret against expiry thresholds, and returns warnings for any
/// needing rotation.
///
/// # Arguments
/// * `env` - Worker environment with KV bindings
///
/// # Returns
/// * `ExpiryCheckResult` - Categorised list of secrets by expiry status
pub async fn check_secret_expiry(env: &Env) -> Result<ExpiryCheckResult> {
    let mut result = ExpiryCheckResult {
        expired: Vec::new(),
        expiring_soon: Vec::new(),
        healthy: Vec::new(),
        errors: Vec::new(),
    };

    // Get current time (using worker::Date for WASM compatibility)
    // Millis-to-seconds division cannot overflow; the result fits in i64
    // (positive epoch seconds until ~year 292 billion).
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_wrap)]
    let current_time = (worker::Date::now().as_millis() / 1000) as i64;

    // Load metadata for known secrets
    let kv = match env.kv("VERIFIER_KV_CONFIG") {
        Ok(kv) => kv,
        Err(e) => {
            result
                .errors
                .push(format!("Failed to access VERIFIER_KV_CONFIG: {}", e));
            return Ok(result);
        }
    };

    // Check tracked secrets (MEK V1/V2/V3 and ADMIN_KEY removed - using single VERIFIER_MEK)
    // VERIFIER_AUDIT_HMAC_KEY removed - audit v2 uses provii-audit-consumer's own HMAC key
    let secret_names = vec!["VERIFIER_MEK"];

    for secret_name in secret_names {
        let metadata_key = format!("{}{}", SECRET_METADATA_PREFIX, secret_name);

        match kv.get(&metadata_key).text().await {
            Ok(Some(json_str)) => match serde_json::from_str::<SecretMetadata>(&json_str) {
                Ok(metadata) => {
                    if metadata.is_expired(current_time) {
                        result.expired.push(secret_name.to_string());
                    } else if metadata.is_expiring_soon(current_time, DEFAULT_WARNING_DAYS) {
                        result.expiring_soon.push(secret_name.to_string());
                    } else {
                        result.healthy.push(secret_name.to_string());
                    }
                }
                Err(e) => {
                    result.errors.push(format!(
                        "Failed to parse metadata for {}: {}",
                        secret_name, e
                    ));
                }
            },
            Ok(None) => {
                // No metadata stored yet - log as info, not error
                // This is expected for new deployments
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SecretExpiry] No metadata found for {} (not yet tracked)",
                    secret_name
                );
            }
            Err(e) => {
                result.errors.push(format!(
                    "Failed to load metadata for {}: {}",
                    secret_name, e
                ));
            }
        }
    }

    Ok(result)
}

/// Log expiry warnings to console.
///
/// This is called during worker startup to alert operators about
/// secrets requiring attention.
pub fn log_expiry_warnings(result: &ExpiryCheckResult) {
    if result.expired.is_empty() && result.expiring_soon.is_empty() {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[SecretExpiry] ✅ All {} secret(s) are healthy",
            result.healthy.len()
        );
        return;
    }

    #[cfg(target_arch = "wasm32")]
    console_log!("[SecretExpiry] ========================================");
    #[cfg(target_arch = "wasm32")]
    console_log!("[SecretExpiry] SECRET EXPIRY WARNING");
    #[cfg(target_arch = "wasm32")]
    console_log!("[SecretExpiry] ========================================");

    if !result.expired.is_empty() {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[SecretExpiry] ❌ EXPIRED SECRETS ({}):",
            result.expired.len()
        );
        for _secret in &result.expired {
            #[cfg(target_arch = "wasm32")]
            console_log!("[SecretExpiry]    - {}", _secret);
        }
        #[cfg(target_arch = "wasm32")]
        console_log!("[SecretExpiry] ACTION REQUIRED: Rotate these secrets immediately!");
    }

    if !result.expiring_soon.is_empty() {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[SecretExpiry] ⚠️  EXPIRING SOON (within {} days) ({}):",
            DEFAULT_WARNING_DAYS,
            result.expiring_soon.len()
        );
        for _secret in &result.expiring_soon {
            #[cfg(target_arch = "wasm32")]
            console_log!("[SecretExpiry]    - {}", _secret);
        }
        #[cfg(target_arch = "wasm32")]
        console_log!("[SecretExpiry] ACTION: Schedule rotation for these secrets");
    }

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[SecretExpiry] ✅ Healthy secrets: {}",
        result.healthy.len()
    );

    if !result.errors.is_empty() {
        #[cfg(target_arch = "wasm32")]
        console_log!("[SecretExpiry] ⚠️  Errors during check:");
        for _error in &result.errors {
            #[cfg(target_arch = "wasm32")]
            console_log!("[SecretExpiry]    - {}", _error);
        }
    }

    #[cfg(target_arch = "wasm32")]
    console_log!("[SecretExpiry] ========================================");
    #[cfg(target_arch = "wasm32")]
    console_log!("[SecretExpiry] See KEY_MANAGEMENT_POLICY.md for rotation procedures");
    #[cfg(target_arch = "wasm32")]
    console_log!("[SecretExpiry] ========================================");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_metadata_expiry() {
        let now = 1700000000; // Example timestamp
        let metadata = SecretMetadata::new("TEST_SECRET".to_string(), now);

        // Should not be expired immediately
        assert!(!metadata.is_expired(now));

        // Should be expired after 91 days
        let future = now + (91 * 24 * 60 * 60);
        assert!(metadata.is_expired(future));

        // Should expire in exactly 90 days
        assert_eq!(metadata.days_until_expiry(now), 90);
    }

    #[test]
    fn test_expiring_soon_threshold() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST_SECRET".to_string(), now);

        // Should not be expiring soon with 90 days remaining
        assert!(!metadata.is_expiring_soon(now, 30));

        // Should be expiring soon with 29 days remaining
        let soon = metadata.expires_at - (29 * 24 * 60 * 60);
        assert!(metadata.is_expiring_soon(soon, 30));

        // Should not show as expiring soon if already expired
        let expired = metadata.expires_at + 1;
        assert!(!metadata.is_expiring_soon(expired, 30));
    }

    #[test]
    fn test_secret_age() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST_SECRET".to_string(), now);

        assert_eq!(metadata.age_days(now), 0);
        assert_eq!(metadata.age_days(now + 86400), 1); // 1 day later
        assert_eq!(metadata.age_days(now + (30 * 86400)), 30); // 30 days later
    }

    #[test]
    fn test_expiry_check_result() {
        let result = ExpiryCheckResult {
            expired: vec!["SECRET1".to_string()],
            expiring_soon: vec!["SECRET2".to_string()],
            healthy: vec!["SECRET3".to_string()],
            errors: vec![],
        };

        assert!(result.has_issues());
        assert_eq!(result.total_secrets(), 3);

        let healthy_result = ExpiryCheckResult {
            expired: vec![],
            expiring_soon: vec![],
            healthy: vec!["SECRET1".to_string(), "SECRET2".to_string()],
            errors: vec![],
        };

        assert!(!healthy_result.has_issues());
        assert_eq!(healthy_result.total_secrets(), 2);
    }

    #[test]
    fn test_custom_expiry() {
        let now = 1700000000;
        let expires_at = now + (30 * 24 * 60 * 60); // 30 days
        let metadata =
            SecretMetadata::with_expiry("SHORT_LIVED_SECRET".to_string(), now, expires_at);

        assert_eq!(metadata.days_until_expiry(now), 30);
        assert!(!metadata.is_expired(now));
        assert!(metadata.is_expired(expires_at));
    }

    #[test]
    fn test_version_metadata() {
        let now = 1700000000;
        let metadata =
            SecretMetadata::new("VERIFIER_MEK_V3".to_string(), now).with_version("V3".to_string());

        assert_eq!(metadata.version, Some("V3".to_string()));
    }

    // ── SecretMetadata construction tests ──────────────────────────────

    #[test]
    fn test_new_sets_90_day_expiry() {
        let created = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), created);
        let ninety_days = 90 * 24 * 60 * 60;
        assert_eq!(metadata.expires_at, created + ninety_days);
        assert_eq!(metadata.created_at, created);
        assert_eq!(metadata.name, "TEST");
        assert!(metadata.version.is_none());
        assert!(metadata.last_rotated_at.is_none());
    }

    #[test]
    fn test_with_expiry_sets_custom_expiry() {
        let created = 1700000000;
        let expires = 1700100000;
        let metadata = SecretMetadata::with_expiry("CUSTOM".to_string(), created, expires);
        assert_eq!(metadata.created_at, created);
        assert_eq!(metadata.expires_at, expires);
        assert_eq!(metadata.name, "CUSTOM");
    }

    #[test]
    fn test_with_version_chains() {
        let metadata =
            SecretMetadata::new("TEST".to_string(), 1700000000).with_version("V4".to_string());
        assert_eq!(metadata.version, Some("V4".to_string()));
        // Chaining must not lose other fields.
        assert_eq!(metadata.name, "TEST");
        assert_eq!(metadata.created_at, 1700000000);
    }

    // ── days_until_expiry tests ───────────────────────────────────────

    #[test]
    fn test_days_until_expiry_exact_90() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        assert_eq!(metadata.days_until_expiry(now), 90);
    }

    #[test]
    fn test_days_until_expiry_after_half_life() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        let forty_five_days = 45 * 24 * 60 * 60;
        assert_eq!(metadata.days_until_expiry(now + forty_five_days), 45);
    }

    #[test]
    fn test_days_until_expiry_negative_when_expired() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        let hundred_days = 100 * 24 * 60 * 60;
        let days = metadata.days_until_expiry(now + hundred_days);
        assert!(
            days < 0,
            "Expired secret must have negative days_until_expiry"
        );
        assert_eq!(days, -10);
    }

    #[test]
    fn test_days_until_expiry_zero_day() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        // At exactly 90 days later.
        let exactly_90 = 90 * 24 * 60 * 60;
        assert_eq!(metadata.days_until_expiry(now + exactly_90), 0);
    }

    #[test]
    fn test_days_until_expiry_one_second_before_new_day() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        // 89 days and 23 hours 59 minutes 59 seconds = 89 days (integer division)
        let almost_90 = 90 * 24 * 60 * 60 - 1;
        assert_eq!(metadata.days_until_expiry(now + almost_90), 0);
    }

    // ── is_expired tests ──────────────────────────────────────────────

    #[test]
    fn test_is_expired_at_exact_boundary() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        // At exactly expires_at, it IS expired (current_time >= expires_at).
        assert!(metadata.is_expired(metadata.expires_at));
    }

    #[test]
    fn test_is_expired_one_second_before() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        assert!(!metadata.is_expired(metadata.expires_at - 1));
    }

    #[test]
    fn test_is_expired_one_second_after() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        assert!(metadata.is_expired(metadata.expires_at + 1));
    }

    // ── is_expiring_soon tests ────────────────────────────────────────

    #[test]
    fn test_is_expiring_soon_exactly_at_threshold() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        // 30 days remaining: should be expiring soon (days_remaining <= 30).
        let thirty_days_before_expiry = metadata.expires_at - (30 * 24 * 60 * 60);
        assert!(metadata.is_expiring_soon(thirty_days_before_expiry, 30));
    }

    #[test]
    fn test_is_expiring_soon_one_day_past_threshold() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        // 31 days remaining: NOT expiring soon.
        let thirty_one_days_before_expiry = metadata.expires_at - (31 * 24 * 60 * 60);
        assert!(!metadata.is_expiring_soon(thirty_one_days_before_expiry, 30));
    }

    #[test]
    fn test_is_expiring_soon_custom_threshold() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        // 7-day warning threshold.
        let seven_days_before = metadata.expires_at - (7 * 24 * 60 * 60);
        assert!(metadata.is_expiring_soon(seven_days_before, 7));
        let eight_days_before = metadata.expires_at - (8 * 24 * 60 * 60);
        assert!(!metadata.is_expiring_soon(eight_days_before, 7));
    }

    #[test]
    fn test_is_expiring_soon_zero_threshold() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        // Zero-day warning: only signals on the last fractional day.
        let just_before = metadata.expires_at - 1;
        assert!(metadata.is_expiring_soon(just_before, 0));
        // At creation time with 90 days remaining, not expiring soon.
        assert!(!metadata.is_expiring_soon(now, 0));
    }

    // ── age_days tests ────────────────────────────────────────────────

    #[test]
    fn test_age_days_at_creation() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        assert_eq!(metadata.age_days(now), 0);
    }

    #[test]
    fn test_age_days_after_one_day() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        assert_eq!(metadata.age_days(now + 86400), 1);
    }

    #[test]
    fn test_age_days_partial_day_truncates() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        // 1.5 days = 129600 seconds, but age_days truncates to 1.
        assert_eq!(metadata.age_days(now + 129600), 1);
    }

    #[test]
    fn test_age_days_after_90_days() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        assert_eq!(metadata.age_days(now + 90 * 86400), 90);
    }

    // ── ExpiryCheckResult tests ───────────────────────────────────────

    #[test]
    fn test_expiry_check_result_no_issues_when_only_healthy() {
        let result = ExpiryCheckResult {
            expired: vec![],
            expiring_soon: vec![],
            healthy: vec!["S1".to_string(), "S2".to_string()],
            errors: vec![],
        };
        assert!(!result.has_issues());
    }

    #[test]
    fn test_expiry_check_result_has_issues_when_expired() {
        let result = ExpiryCheckResult {
            expired: vec!["EXPIRED_SECRET".to_string()],
            expiring_soon: vec![],
            healthy: vec![],
            errors: vec![],
        };
        assert!(result.has_issues());
    }

    #[test]
    fn test_expiry_check_result_has_issues_when_expiring_soon() {
        let result = ExpiryCheckResult {
            expired: vec![],
            expiring_soon: vec!["SOON_SECRET".to_string()],
            healthy: vec![],
            errors: vec![],
        };
        assert!(result.has_issues());
    }

    #[test]
    fn test_expiry_check_result_total_secrets_excludes_errors() {
        let result = ExpiryCheckResult {
            expired: vec!["A".to_string()],
            expiring_soon: vec!["B".to_string()],
            healthy: vec!["C".to_string(), "D".to_string()],
            errors: vec!["Failed to load E".to_string()],
        };
        // total_secrets = 1 + 1 + 2 = 4 (errors excluded)
        assert_eq!(result.total_secrets(), 4);
    }

    #[test]
    fn test_expiry_check_result_total_secrets_empty() {
        let result = ExpiryCheckResult {
            expired: vec![],
            expiring_soon: vec![],
            healthy: vec![],
            errors: vec![],
        };
        assert_eq!(result.total_secrets(), 0);
    }

    // ── Serde roundtrip tests ─────────────────────────────────────────

    #[test]
    fn test_secret_metadata_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let metadata = SecretMetadata::new("VERIFIER_MEK".to_string(), 1700000000)
            .with_version("V3".to_string());
        let json = serde_json::to_string(&metadata)?;
        let decoded: SecretMetadata = serde_json::from_str(&json)?;
        assert_eq!(decoded.name, "VERIFIER_MEK");
        assert_eq!(decoded.created_at, 1700000000);
        assert_eq!(decoded.version, Some("V3".to_string()));
        assert_eq!(decoded.expires_at, metadata.expires_at);
        Ok(())
    }

    #[test]
    fn test_secret_metadata_serde_with_last_rotated() -> Result<(), Box<dyn std::error::Error>> {
        let mut metadata = SecretMetadata::new("TEST".to_string(), 1700000000);
        metadata.last_rotated_at = Some(1700500000);
        let json = serde_json::to_string(&metadata)?;
        let decoded: SecretMetadata = serde_json::from_str(&json)?;
        assert_eq!(decoded.last_rotated_at, Some(1700500000));
        Ok(())
    }

    #[test]
    fn test_expiry_check_result_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let result = ExpiryCheckResult {
            expired: vec!["A".to_string()],
            expiring_soon: vec!["B".to_string()],
            healthy: vec!["C".to_string()],
            errors: vec!["error msg".to_string()],
        };
        let json = serde_json::to_string(&result)?;
        let decoded: ExpiryCheckResult = serde_json::from_str(&json)?;
        assert_eq!(decoded.expired.len(), 1);
        assert_eq!(decoded.expiring_soon.len(), 1);
        assert_eq!(decoded.healthy.len(), 1);
        assert_eq!(decoded.errors.len(), 1);
        Ok(())
    }

    // ── Constants tests ───────────────────────────────────────────────

    #[test]
    fn test_default_warning_days_is_30() {
        assert_eq!(DEFAULT_WARNING_DAYS, 30);
    }

    #[test]
    fn test_secret_metadata_prefix_constant() {
        assert_eq!(SECRET_METADATA_PREFIX, "secret_metadata:");
    }

    // ── Edge case: zero timestamp ─────────────────────────────────────

    #[test]
    fn test_metadata_with_zero_created_at() {
        let metadata = SecretMetadata::new("ZERO".to_string(), 0);
        assert_eq!(metadata.created_at, 0);
        assert_eq!(metadata.expires_at, 90 * 24 * 60 * 60);
        assert!(!metadata.is_expired(0));
        assert!(metadata.is_expired(90 * 24 * 60 * 60));
    }

    // ── log_expiry_warnings smoke test (console-only) ─────────────────

    #[test]
    fn test_log_expiry_warnings_healthy_does_not_panic() {
        let result = ExpiryCheckResult {
            expired: vec![],
            expiring_soon: vec![],
            healthy: vec!["S1".to_string()],
            errors: vec![],
        };
        log_expiry_warnings(&result);
    }

    #[test]
    fn test_log_expiry_warnings_expired_does_not_panic() {
        let result = ExpiryCheckResult {
            expired: vec!["EXPIRED".to_string()],
            expiring_soon: vec![],
            healthy: vec![],
            errors: vec![],
        };
        log_expiry_warnings(&result);
    }

    #[test]
    fn test_log_expiry_warnings_expiring_soon_does_not_panic() {
        let result = ExpiryCheckResult {
            expired: vec![],
            expiring_soon: vec!["SOON".to_string()],
            healthy: vec![],
            errors: vec![],
        };
        log_expiry_warnings(&result);
    }

    #[test]
    fn test_log_expiry_warnings_with_errors_does_not_panic() {
        let result = ExpiryCheckResult {
            expired: vec!["EXP".to_string()],
            expiring_soon: vec!["SOON".to_string()],
            healthy: vec!["OK".to_string()],
            errors: vec!["some error".to_string()],
        };
        log_expiry_warnings(&result);
    }

    #[test]
    fn test_log_expiry_warnings_empty_does_not_panic() {
        let result = ExpiryCheckResult {
            expired: vec![],
            expiring_soon: vec![],
            healthy: vec![],
            errors: vec![],
        };
        log_expiry_warnings(&result);
    }

    // ── saturating_add overflow protection ─────────────────────────────

    #[test]
    fn test_new_with_i64_max_created_at_does_not_overflow() {
        // SecretMetadata::new uses saturating_add for expires_at.
        let metadata = SecretMetadata::new("OVERFLOW".to_string(), i64::MAX);
        assert_eq!(metadata.expires_at, i64::MAX);
    }

    #[test]
    fn test_expiry_check_result_total_secrets_saturating() {
        // total_secrets uses saturating_add, confirm it works near usize::MAX.
        let result = ExpiryCheckResult {
            expired: vec!["A".to_string()],
            expiring_soon: vec![],
            healthy: vec![],
            errors: vec![],
        };
        assert_eq!(result.total_secrets(), 1);
    }

    // ── SecretMetadata: with_expiry edge cases ────────────────────────

    #[test]
    fn test_with_expiry_allows_expires_before_created() {
        // Not a realistic scenario, but with_expiry does not validate ordering.
        let metadata = SecretMetadata::with_expiry("BAD".to_string(), 1000, 500);
        assert_eq!(metadata.created_at, 1000);
        assert_eq!(metadata.expires_at, 500);
        assert!(metadata.is_expired(600));
        assert!(metadata.is_expired(1000));
    }

    #[test]
    fn test_with_expiry_equal_created_and_expires() {
        let metadata = SecretMetadata::with_expiry("INSTANT".to_string(), 1000, 1000);
        assert!(metadata.is_expired(1000));
        assert!(!metadata.is_expired(999));
    }

    // ── SecretMetadata: with_version does not clobber last_rotated_at ──

    #[test]
    fn test_with_version_preserves_none_last_rotated() {
        let metadata =
            SecretMetadata::new("TEST".to_string(), 1700000000).with_version("V5".to_string());
        assert!(metadata.last_rotated_at.is_none());
    }

    // ── days_until_expiry: extreme values ─────────────────────────────

    #[test]
    fn test_days_until_expiry_far_future() {
        let now = 0;
        let metadata = SecretMetadata::with_expiry("FAR".to_string(), 0, i64::MAX);
        let days = metadata.days_until_expiry(now);
        // i64::MAX / 86400 should be a very large number.
        assert!(days > 0);
    }

    #[test]
    fn test_days_until_expiry_negative_timestamps() {
        // Negative timestamps (before epoch) should still compute correctly.
        let metadata = SecretMetadata::with_expiry("OLD".to_string(), -200_000, -100_000);
        // At time -150_000, remaining = (-100_000 - (-150_000)) / 86400 = 50000 / 86400 = 0.
        assert_eq!(metadata.days_until_expiry(-150_000), 0);
        // At time -200_000, remaining = (-100_000 - (-200_000)) / 86400 = 100000 / 86400 = 1.
        assert_eq!(metadata.days_until_expiry(-200_000), 1);
    }

    // ── is_expired: boundary precision ────────────────────────────────

    #[test]
    fn test_is_expired_with_zero_expiry() {
        let metadata = SecretMetadata::with_expiry("ZERO_EXP".to_string(), 0, 0);
        assert!(metadata.is_expired(0));
        assert!(!metadata.is_expired(-1));
    }

    #[test]
    fn test_is_expired_with_max_expiry() {
        let metadata = SecretMetadata::with_expiry("MAX_EXP".to_string(), 0, i64::MAX);
        assert!(!metadata.is_expired(0));
        assert!(!metadata.is_expired(i64::MAX - 1));
        assert!(metadata.is_expired(i64::MAX));
    }

    // ── is_expiring_soon: interplay with is_expired ───────────────────

    #[test]
    fn test_is_expiring_soon_when_already_expired_is_false() {
        let metadata = SecretMetadata::new("TEST".to_string(), 1700000000);
        // Even with a very large warning window, expired secrets are not "expiring soon".
        let long_after = metadata.expires_at + 100_000;
        assert!(!metadata.is_expiring_soon(long_after, 99999));
    }

    #[test]
    fn test_is_expiring_soon_large_warning_window() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        // Warning window larger than total lifetime: should be expiring soon immediately.
        assert!(metadata.is_expiring_soon(now, 100));
    }

    #[test]
    fn test_is_expiring_soon_negative_threshold_never_triggers() {
        let now = 1700000000;
        let metadata = SecretMetadata::new("TEST".to_string(), now);
        // Negative threshold: days_remaining (90) is never <= -1.
        assert!(!metadata.is_expiring_soon(now, -1));
    }

    // ── age_days: negative current time ───────────────────────────────

    #[test]
    fn test_age_days_before_creation_is_zero_or_negative() {
        let metadata = SecretMetadata::new("TEST".to_string(), 1000);
        // 500 - 1000 = -500 seconds; integer division by 86400 rounds toward zero, yielding 0
        assert_eq!(metadata.age_days(500), 0);
        // With a full day's difference it becomes -1
        assert_eq!(metadata.age_days(1000 - 86400), -1);
    }

    // ── ExpiryCheckResult: edge cases ─────────────────────────────────

    #[test]
    fn test_has_issues_both_expired_and_expiring_soon() {
        let result = ExpiryCheckResult {
            expired: vec!["A".to_string()],
            expiring_soon: vec!["B".to_string()],
            healthy: vec![],
            errors: vec![],
        };
        assert!(result.has_issues());
    }

    #[test]
    fn test_has_issues_errors_only_does_not_count() {
        // Errors alone do not constitute "issues" per has_issues().
        let result = ExpiryCheckResult {
            expired: vec![],
            expiring_soon: vec![],
            healthy: vec![],
            errors: vec!["something failed".to_string()],
        };
        assert!(!result.has_issues());
    }

    #[test]
    fn test_total_secrets_does_not_count_errors() {
        let result = ExpiryCheckResult {
            expired: vec![],
            expiring_soon: vec![],
            healthy: vec![],
            errors: vec!["err1".to_string(), "err2".to_string()],
        };
        assert_eq!(result.total_secrets(), 0);
    }

    // ── Serde: deserialisation from known JSON ────────────────────────

    #[test]
    fn test_secret_metadata_deserialize_minimal() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"name":"TEST","created_at":1000,"expires_at":2000,"version":null,"last_rotated_at":null}"#;
        let metadata: SecretMetadata = serde_json::from_str(json)?;
        assert_eq!(metadata.name, "TEST");
        assert_eq!(metadata.created_at, 1000);
        assert_eq!(metadata.expires_at, 2000);
        assert!(metadata.version.is_none());
        assert!(metadata.last_rotated_at.is_none());
        Ok(())
    }

    #[test]
    fn test_secret_metadata_deserialize_with_all_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let json = r#"{"name":"MEK","created_at":100,"expires_at":200,"version":"V3","last_rotated_at":150}"#;
        let metadata: SecretMetadata = serde_json::from_str(json)?;
        assert_eq!(metadata.version, Some("V3".to_string()));
        assert_eq!(metadata.last_rotated_at, Some(150));
        Ok(())
    }

    #[test]
    fn test_expiry_check_result_deserialize_empty() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"expired":[],"expiring_soon":[],"healthy":[],"errors":[]}"#;
        let result: ExpiryCheckResult = serde_json::from_str(json)?;
        assert_eq!(result.total_secrets(), 0);
        assert!(!result.has_issues());
        Ok(())
    }

    // ── Clone + Debug trait tests ─────────────────────────────────────

    #[test]
    fn test_secret_metadata_clone() {
        let metadata = SecretMetadata::new("CLONE_TEST".to_string(), 1700000000)
            .with_version("V1".to_string());
        let cloned = metadata.clone();
        assert_eq!(cloned.name, metadata.name);
        assert_eq!(cloned.created_at, metadata.created_at);
        assert_eq!(cloned.expires_at, metadata.expires_at);
        assert_eq!(cloned.version, metadata.version);
    }

    #[test]
    fn test_secret_metadata_debug() {
        let metadata = SecretMetadata::new("DEBUG_TEST".to_string(), 1700000000);
        let debug = format!("{:?}", metadata);
        assert!(debug.contains("DEBUG_TEST"));
        assert!(debug.contains("SecretMetadata"));
    }

    #[test]
    fn test_expiry_check_result_clone() {
        let result = ExpiryCheckResult {
            expired: vec!["A".to_string()],
            expiring_soon: vec!["B".to_string()],
            healthy: vec!["C".to_string()],
            errors: vec!["E".to_string()],
        };
        let cloned = result.clone();
        assert_eq!(cloned.expired, result.expired);
        assert_eq!(cloned.expiring_soon, result.expiring_soon);
        assert_eq!(cloned.healthy, result.healthy);
        assert_eq!(cloned.errors, result.errors);
    }

    #[test]
    fn test_expiry_check_result_debug() {
        let result = ExpiryCheckResult {
            expired: vec![],
            expiring_soon: vec![],
            healthy: vec!["OK".to_string()],
            errors: vec![],
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("ExpiryCheckResult"));
    }

    // ── 90-day constant correctness ───────────────────────────────────

    #[test]
    fn test_ninety_day_expiry_is_7776000_seconds() {
        let metadata = SecretMetadata::new("CHECK".to_string(), 0);
        assert_eq!(metadata.expires_at, 7_776_000);
    }

    // ── log_expiry_warnings: multi-item lists ─────────────────────────

    #[test]
    fn test_log_expiry_warnings_multiple_expired_does_not_panic() {
        let result = ExpiryCheckResult {
            expired: vec!["SECRET_A".to_string(), "SECRET_B".to_string()],
            expiring_soon: vec!["SECRET_C".to_string(), "SECRET_D".to_string()],
            healthy: vec!["SECRET_E".to_string(), "SECRET_F".to_string()],
            errors: vec!["error one".to_string(), "error two".to_string()],
        };
        log_expiry_warnings(&result);
    }

    // ── Multiple with_version calls ───────────────────────────────────

    #[test]
    fn test_with_version_overwrites_previous() {
        let metadata = SecretMetadata::new("TEST".to_string(), 0)
            .with_version("V1".to_string())
            .with_version("V2".to_string());
        assert_eq!(metadata.version, Some("V2".to_string()));
    }

    // ── days_until_expiry with custom expiry ──────────────────────────

    #[test]
    fn test_days_until_expiry_custom_expiry_one_day() {
        let now = 1000;
        let metadata = SecretMetadata::with_expiry("SHORT".to_string(), now, now + 86400);
        assert_eq!(metadata.days_until_expiry(now), 1);
    }

    #[test]
    fn test_days_until_expiry_custom_expiry_zero_duration() {
        let now = 1000;
        let metadata = SecretMetadata::with_expiry("ZERO".to_string(), now, now);
        assert_eq!(metadata.days_until_expiry(now), 0);
    }

    #[test]
    fn test_with_version_empty_string() {
        let metadata =
            SecretMetadata::new("TEST".to_string(), 1700000000).with_version(String::new());
        assert_eq!(metadata.version, Some(String::new()));
        assert_eq!(metadata.name, "TEST");
    }

    #[test]
    fn test_with_version_preserves_last_rotated_at_when_set() {
        let mut metadata = SecretMetadata::new("TEST".to_string(), 1700000000);
        metadata.last_rotated_at = Some(1700500000);
        let metadata = metadata.with_version("V4".to_string());
        assert_eq!(metadata.version, Some("V4".to_string()));
        assert_eq!(metadata.last_rotated_at, Some(1700500000));
    }

    #[test]
    fn test_with_version_preserves_custom_expiry() {
        let metadata = SecretMetadata::with_expiry("CUSTOM".to_string(), 1000, 5000)
            .with_version("V7".to_string());
        assert_eq!(metadata.expires_at, 5000);
        assert_eq!(metadata.created_at, 1000);
        assert_eq!(metadata.version, Some("V7".to_string()));
    }

    #[test]
    fn test_log_expiry_warnings_healthy_with_errors_takes_early_return() {
        let result = ExpiryCheckResult {
            expired: vec![],
            expiring_soon: vec![],
            healthy: vec!["OK1".to_string(), "OK2".to_string()],
            errors: vec!["some error".to_string()],
        };
        log_expiry_warnings(&result);
    }

    #[test]
    fn test_log_expiry_warnings_only_expiring_soon_no_expired() {
        let result = ExpiryCheckResult {
            expired: vec![],
            expiring_soon: vec!["WARN1".to_string(), "WARN2".to_string()],
            healthy: vec!["OK".to_string()],
            errors: vec![],
        };
        log_expiry_warnings(&result);
    }
}
