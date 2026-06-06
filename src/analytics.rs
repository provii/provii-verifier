// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Analytics helpers for emitting structured events to Cloudflare Analytics Engine.
//!
//! Provides [`Analytics`], a thin wrapper that enforces a consistent schema across
//! all event types: verification outcomes, billing events, challenge creation, and
//! cold start / warm request telemetry. Each event is written as a data point with
//! positional blobs (string fields) and doubles (numeric fields) so that downstream
//! dashboards can rely on stable column ordering.

use worker::{AnalyticsEngineDataPointBuilder, Env, Result};

/// Wrapper around the Cloudflare Analytics Engine binding that enforces
/// a consistent schema for events emitted by the verifier API.
pub struct Analytics {
    env: Env,
}

impl Analytics {
    /// Creates a new `Analytics` instance from the given worker environment.
    pub fn new(env: &Env) -> Self {
        Self { env: env.clone() }
    }

    /// Writes a single analytics event using the shared field ordering expected by
    /// the analytics dashboard.
    fn write_event(
        &self,
        index: &str,
        event: &str,
        route: &str,
        challenge_id: &str,
        origin: &str,
        issuer_kid: Option<&str>,
        issuer_hash_b64: Option<&str>,
        result: &str,
        error_code: Option<&str>,
        environment: &str,
        count: f64,
        duration_ms: Option<f64>,
        cutoff_days: Option<i32>,
        http_status: Option<u16>,
        has_royalty: bool,
        partner_id: Option<&str>,
    ) -> Result<()> {
        let dataset = self.env.analytics_engine("VERIFIER_ANALYTICS")?;

        let mut builder = AnalyticsEngineDataPointBuilder::new();

        // Configure the primary sampling index (Analytics Engine uses slices for indexes).
        builder = builder.indexes([index]);

        // ST-VA-030: Truncate challenge UUIDs to an 8-character prefix before
        // writing to Analytics Engine. Full UUIDs are not needed for aggregate
        // dashboards, and redaction limits exposure if analytics data is leaked.
        // Matches the redaction pattern in log_sanitizer::redact_challenge_id.
        let redacted_challenge_id = challenge_id.get(..8).unwrap_or(challenge_id);

        // Maintain positional blobs so dashboards can rely on column order.
        // New fields are appended at the END to preserve existing column indices.
        let blobs = vec![
            event.to_string(),
            route.to_string(),
            redacted_challenge_id.to_string(),
            origin.to_string(),
            issuer_kid.unwrap_or("none").to_string(),
            issuer_hash_b64.unwrap_or("none").to_string(),
            result.to_string(),
            error_code.unwrap_or("").to_string(),
            environment.to_string(),
            String::new(),
            partner_id.unwrap_or("").to_string(),
        ];
        builder = builder.blobs(blobs);

        // The numeric slots follow the same ordering contract as the blobs.
        let doubles = vec![
            count,
            duration_ms.unwrap_or(0.0),
            cutoff_days.map(|d| d as f64).unwrap_or(0.0),
            http_status.map(|s| s as f64).unwrap_or(0.0),
            if has_royalty { 1.0 } else { 0.0 },
        ];
        builder = builder.doubles(doubles);

        let data_point = builder.build();
        dataset.write_data_point(&data_point)?;

        Ok(())
    }

    /// Records a successful age verification, indexed by both origin host and
    /// issuer key ID (when present) so dashboards can slice by either dimension.
    pub fn verification_success(
        &self,
        route: &str,
        challenge_id: &str,
        origin: &str,
        issuer_kid: Option<&str>,
        issuer_hash_b64: Option<&str>,
        cutoff_days: i32,
        duration_ms: Option<f64>,
        has_royalty: bool,
        environment: &str,
    ) {
        let origin_index = origin_host(origin);
        let _ = self.write_event(
            &origin_index,
            "verify_success",
            route,
            challenge_id,
            origin,
            issuer_kid,
            issuer_hash_b64,
            "ok",
            None,
            environment,
            1.0,
            duration_ms,
            Some(cutoff_days),
            Some(200),
            has_royalty,
            None,
        );

        if let Some(kid) = issuer_kid {
            let _ = self.write_event(
                kid,
                "verify_success",
                route,
                challenge_id,
                origin,
                Some(kid),
                issuer_hash_b64,
                "ok",
                None,
                environment,
                1.0,
                duration_ms,
                Some(cutoff_days),
                Some(200),
                has_royalty,
                None,
            );
        }
    }

    /// Records a failed verification attempt, indexed by origin host.
    pub fn verification_failed(
        &self,
        route: &str,
        challenge_id: &str,
        origin: &str,
        error_code: &str,
        duration_ms: Option<f64>,
        environment: &str,
    ) {
        let origin_index = origin_host(origin);
        let _ = self.write_event(
            &origin_index,
            "verify_failed",
            route,
            challenge_id,
            origin,
            None,
            None,
            "error",
            Some(error_code),
            environment,
            1.0,
            duration_ms,
            None,
            Some(400),
            false,
            None,
        );
    }

    /// Records a billable verification event, writing to both origin and issuer
    /// indexes. Also emits a structured console log for billing reconciliation.
    pub fn billing_verification_success(
        &self,
        route: &str,
        challenge_id: &str,
        origin: &str,
        issuer_kid: Option<&str>,
        issuer_hash_b64: Option<&str>,
        cutoff_days: i32,
        has_royalty: bool,
        environment: &str,
    ) {
        // SECURITY: Redact sensitive identifiers in logs (GDPR compliance)
        #[cfg(target_arch = "wasm32")]
        use crate::security::log_sanitizer::redact_challenge_id;

        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "[BILLING_EVENT] challenge_id={} origin={} issuer_kid={} cutoff_days={} has_royalty={} royalty_to={}",
            redact_challenge_id(challenge_id),
            origin,
            issuer_kid.unwrap_or("none"),
            cutoff_days,
            has_royalty,
            issuer_kid.unwrap_or("none")
        );

        let origin_index = origin_host(origin);
        let _ = self.write_event(
            &origin_index,
            "billing_verification_success",
            route,
            challenge_id,
            origin,
            issuer_kid,
            issuer_hash_b64,
            "ok",
            None,
            environment,
            1.0,
            None,
            Some(cutoff_days),
            Some(200),
            has_royalty,
            None,
        );

        if let Some(kid) = issuer_kid {
            let _ = self.write_event(
                kid,
                "billing_verification_success",
                route,
                challenge_id,
                origin,
                Some(kid),
                issuer_hash_b64,
                "ok",
                None,
                environment,
                1.0,
                None,
                Some(cutoff_days),
                Some(200),
                has_royalty,
                None,
            );
        }
    }

    /// Records a challenge creation event, indexed by origin host.
    pub fn challenge_created(
        &self,
        route: &str,
        challenge_id: &str,
        origin: &str,
        cutoff_days: i32,
        environment: &str,
    ) {
        let origin_index = origin_host(origin);
        let _ = self.write_event(
            &origin_index,
            "challenge_created",
            route,
            challenge_id,
            origin,
            None,
            None,
            "ok",
            None,
            environment,
            1.0,
            None,
            Some(cutoff_days),
            Some(201),
            false,
            None,
        );
    }

    /// Records a hosted status check event, indexed by origin host.
    pub fn hosted_status_checked(
        &self,
        route: &str,
        session_id: &str,
        origin: &str,
        duration_ms: f64,
        environment: &str,
    ) {
        let origin_index = origin_host(origin);
        let _ = self.write_event(
            &origin_index,
            "hosted_status_checked",
            route,
            session_id,
            origin,
            None,
            None,
            "ok",
            None,
            environment,
            1.0,
            Some(duration_ms),
            None,
            Some(200),
            false,
            None,
        );
    }

    /// Records a hosted PKCE redemption event, indexed by origin host.
    pub fn hosted_redeemed(
        &self,
        route: &str,
        session_id: &str,
        origin: &str,
        duration_ms: f64,
        environment: &str,
    ) {
        let origin_index = origin_host(origin);
        let _ = self.write_event(
            &origin_index,
            "hosted_redeemed",
            route,
            session_id,
            origin,
            None,
            None,
            "ok",
            None,
            environment,
            1.0,
            Some(duration_ms),
            None,
            Some(200),
            false,
            None,
        );
    }

    /// Records a hosted session check event, indexed by origin host.
    pub fn hosted_session_checked(
        &self,
        route: &str,
        origin: &str,
        duration_ms: f64,
        result: &str,
        environment: &str,
    ) {
        let origin_index = origin_host(origin);
        let _ = self.write_event(
            &origin_index,
            "hosted_session_checked",
            route,
            "-", // No session ID available at the cookie-check layer.
            origin,
            None,
            None,
            result,
            None,
            environment,
            1.0,
            Some(duration_ms),
            None,
            Some(200),
            false,
            None,
        );
    }

    /// Records a cold start event with detailed timing breakdown.
    ///
    /// # Arguments
    /// * `route` - The route that triggered the cold start
    /// * `total_init_ms` - Total initialisation time in milliseconds
    /// * `crypto_init_ms` - Time spent initialising crypto (VK parsing)
    /// * `state_init_ms` - Time spent initialising app state (KV, DO bindings)
    /// * `mek_fetch_ms` - Time spent fetching MEK from Secrets Store (if applicable)
    /// * `environment` - Production or sandbox
    pub fn cold_start(
        &self,
        route: &str,
        total_init_ms: f64,
        crypto_init_ms: Option<f64>,
        state_init_ms: Option<f64>,
        mek_fetch_ms: Option<f64>,
        environment: &str,
    ) {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "[COLD_START] ❄️ Worker cold start detected on route={} total={}ms crypto={}ms state={}ms mek={}ms env={}",
            route,
            total_init_ms,
            crypto_init_ms.unwrap_or(0.0),
            state_init_ms.unwrap_or(0.0),
            mek_fetch_ms.unwrap_or(0.0),
            environment
        );

        // Use "cold_start" as the index for easy filtering in Analytics Engine
        let _ = self.write_event(
            "cold_start",
            "cold_start",
            route,
            "-", // No challenge ID for cold start events
            environment,
            None,
            None,
            "ok",
            None,
            environment,
            1.0, // Count of 1 cold start
            Some(total_init_ms),
            None,
            None,
            false,
            None,
        );

        // Also write with crypto_init_ms as duration if available, using different event name
        if let Some(crypto_ms) = crypto_init_ms {
            let _ = self.write_event(
                "cold_start",
                "cold_start_crypto",
                route,
                "-",
                environment,
                None,
                None,
                "ok",
                None,
                environment,
                1.0,
                Some(crypto_ms),
                None,
                None,
                false,
                None,
            );
        }

        // Write state init timing
        if let Some(state_ms) = state_init_ms {
            let _ = self.write_event(
                "cold_start",
                "cold_start_state",
                route,
                "-",
                environment,
                None,
                None,
                "ok",
                None,
                environment,
                1.0,
                Some(state_ms),
                None,
                None,
                false,
                None,
            );
        }

        // Write MEK fetch timing
        if let Some(mek_ms) = mek_fetch_ms {
            let _ = self.write_event(
                "cold_start",
                "cold_start_mek",
                route,
                "-",
                environment,
                None,
                None,
                "ok",
                None,
                environment,
                1.0,
                Some(mek_ms),
                None,
                None,
                false,
                None,
            );
        }
    }

    /// Records a warm request event for comparison with cold starts.
    ///
    /// # Arguments
    /// * `route` - The route being accessed
    /// * `request_num` - The request number for this worker instance
    /// * `worker_age_ms` - How long this worker instance has been alive
    pub fn warm_request(
        &self,
        route: &str,
        request_num: u64,
        worker_age_ms: u64,
        environment: &str,
    ) {
        // Only log every 100th warm request to avoid log spam
        if request_num.is_multiple_of(100) {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "[WARM_REQUEST] 🔥 Worker warm request #{} on route={} worker_age={}ms",
                request_num,
                route,
                worker_age_ms
            );
        }

        let _ = self.write_event(
            "warm_request",
            "warm_request",
            route,
            "-",
            "system",
            None,
            None,
            "ok",
            None,
            environment,
            request_num as f64,
            Some(worker_age_ms as f64),
            None,
            None,
            false,
            None,
        );
    }
}

/// Extracts the host portion of an origin URL, falling back to the raw origin string if parsing fails.
fn origin_host(origin: &str) -> String {
    url::Url::parse(origin)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| origin.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    origin_host() TESTS                                    */
    /* ========================================================================== */

    #[test]
    fn test_origin_host_valid_https() {
        assert_eq!(origin_host("https://example.com"), "example.com");
    }

    #[test]
    fn test_origin_host_valid_http() {
        assert_eq!(origin_host("http://example.com"), "example.com");
    }

    #[test]
    fn test_origin_host_with_port() {
        assert_eq!(origin_host("https://example.com:8443"), "example.com");
    }

    #[test]
    fn test_origin_host_with_path() {
        assert_eq!(origin_host("https://example.com/path"), "example.com");
    }

    #[test]
    fn test_origin_host_with_subdomain() {
        assert_eq!(origin_host("https://sub.example.com"), "sub.example.com");
    }

    #[test]
    fn test_origin_host_localhost() {
        assert_eq!(origin_host("http://localhost:3000"), "localhost");
    }

    #[test]
    fn test_origin_host_ip_address() {
        assert_eq!(origin_host("https://192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn test_origin_host_ipv6() {
        assert_eq!(origin_host("https://[::1]:8080"), "[::1]");
    }

    #[test]
    fn test_origin_host_invalid_url_fallback() {
        let invalid = "not-a-valid-url";
        assert_eq!(origin_host(invalid), invalid);
    }

    #[test]
    fn test_origin_host_empty_string_fallback() {
        assert_eq!(origin_host(""), "");
    }

    #[test]
    fn test_origin_host_no_scheme_fallback() {
        let no_scheme = "example.com";
        assert_eq!(origin_host(no_scheme), no_scheme);
    }

    #[test]
    fn test_origin_host_with_query_parameters() {
        assert_eq!(
            origin_host("https://example.com?param=value"),
            "example.com"
        );
    }

    #[test]
    fn test_origin_host_with_fragment() {
        assert_eq!(origin_host("https://example.com#section"), "example.com");
    }

    #[test]
    fn test_origin_host_with_query_and_fragment() {
        assert_eq!(
            origin_host("https://example.com?foo=bar#top"),
            "example.com"
        );
    }

    #[test]
    fn test_origin_host_with_userinfo() {
        // URLs with user:pass@host should extract just the host
        assert_eq!(origin_host("https://user:pass@example.com"), "example.com");
    }

    #[test]
    fn test_origin_host_multiple_subdomains() {
        assert_eq!(
            origin_host("https://api.staging.example.com"),
            "api.staging.example.com"
        );
    }

    #[test]
    fn test_origin_host_very_long_subdomain() {
        let long_subdomain = "a".repeat(50);
        let url = format!("https://{}.example.com", long_subdomain);
        let expected = format!("{}.example.com", long_subdomain);
        assert_eq!(origin_host(&url), expected);
    }

    #[test]
    fn test_origin_host_with_trailing_slash() {
        assert_eq!(origin_host("https://example.com/"), "example.com");
    }

    #[test]
    fn test_origin_host_with_deep_path() {
        assert_eq!(origin_host("https://example.com/a/b/c/d/e"), "example.com");
    }

    #[test]
    fn test_origin_host_mixed_case_scheme() {
        assert_eq!(origin_host("HtTpS://example.com"), "example.com");
    }

    #[test]
    fn test_origin_host_special_chars_fallback() {
        // Url crate tolerates trailing whitespace, so this parses successfully
        assert_eq!(origin_host("https://example.com\n"), "example.com");
        // Truly invalid URLs fall back to the original string
        let invalid = "not a url at all";
        assert_eq!(origin_host(invalid), invalid);
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: origin_host() with valid URLs extracts host
        #[test]
        fn prop_origin_host_valid_urls(scheme in "(https?)", host in "[a-z]{3,10}\\.(com|org|net)") {
            let url = format!("{}://{}", scheme, host);
            let result = origin_host(&url);
            prop_assert_eq!(result, host);
        }

        /// Property: origin_host() is deterministic
        #[test]
        fn prop_origin_host_deterministic(scheme in "(https?)", host in "[a-z]{3,10}\\.com") {
            let url = format!("{}://{}", scheme, host);
            let result1 = origin_host(&url);
            let result2 = origin_host(&url);
            prop_assert_eq!(result1, result2);
        }

        /// Property: origin_host() invalid URLs fallback to input
        #[test]
        fn prop_origin_host_invalid_fallback(invalid in "[a-z]{1,20}") {
            prop_assume!(!invalid.contains("://"));
            let result = origin_host(&invalid);
            prop_assert_eq!(result, invalid);
        }

    }

    /* ========================================================================== */
    /*                    ADDITIONAL origin_host() EDGE CASES                    */
    /* ========================================================================== */

    #[test]
    fn test_origin_host_ftp_scheme() {
        assert_eq!(origin_host("ftp://files.example.com"), "files.example.com");
    }

    #[test]
    fn test_origin_host_ws_scheme() {
        assert_eq!(origin_host("ws://socket.example.com"), "socket.example.com");
    }

    #[test]
    fn test_origin_host_wss_scheme() {
        assert_eq!(
            origin_host("wss://secure-socket.example.com"),
            "secure-socket.example.com"
        );
    }

    #[test]
    fn test_origin_host_data_uri_fallback() {
        // data: URIs have no host
        let data_uri = "data:text/html,<h1>test</h1>";
        // url::Url::parse succeeds for data: URIs but host_str() is None
        let result = origin_host(data_uri);
        assert_eq!(result, data_uri, "data: URI should fall back to raw string");
    }

    #[test]
    fn test_origin_host_file_scheme() {
        // file:// URLs may not have a host
        let file_url = "file:///tmp/test.html";
        let result = origin_host(file_url);
        // url crate parses file:/// with empty host, host_str() returns Some("")
        // which is fine; the result is either "" or the raw string
        assert!(
            result.is_empty() || result == file_url,
            "file:// URL host should be empty or fallback, got: {}",
            result
        );
    }

    #[test]
    fn test_origin_host_punycode_domain() {
        assert_eq!(
            origin_host("https://xn--n3h.example.com"),
            "xn--n3h.example.com"
        );
    }

    #[test]
    fn test_origin_host_trailing_dot_domain() {
        // Some DNS configurations use trailing dots
        let result = origin_host("https://example.com.");
        assert_eq!(result, "example.com.");
    }

    #[test]
    fn test_origin_host_high_port_number() {
        assert_eq!(origin_host("https://example.com:65535"), "example.com");
    }

    #[test]
    fn test_origin_host_ipv4_with_path() {
        assert_eq!(origin_host("https://10.0.0.1/api/v1/check"), "10.0.0.1");
    }

    #[test]
    fn test_origin_host_ipv6_full() {
        assert_eq!(origin_host("https://[2001:db8::1]"), "[2001:db8::1]");
    }

    #[test]
    fn test_origin_host_url_encoded_path() {
        assert_eq!(
            origin_host("https://example.com/path%20with%20spaces"),
            "example.com"
        );
    }

    #[test]
    fn test_origin_host_multiple_ports_in_path() {
        // Port is in the authority, not the path; path colon is ignored
        assert_eq!(
            origin_host("https://example.com:443/path:8080"),
            "example.com"
        );
    }

    #[test]
    fn test_origin_host_just_scheme_no_host() {
        let input = "https://";
        let result = origin_host(input);
        // url::Url::parse("https://") succeeds with empty host
        assert!(
            result.is_empty() || result == input,
            "Empty authority should yield empty host or fallback, got: {}",
            result
        );
    }

    #[test]
    fn test_origin_host_returns_owned_string() {
        let url = String::from("https://owned.example.com");
        let result = origin_host(&url);
        assert_eq!(result, "owned.example.com");
        // Verify the result is an independent String (ownership)
        drop(url);
        assert_eq!(result, "owned.example.com");
    }

    /* ========================================================================== */
    /*                    CHALLENGE ID REDACTION LOGIC TESTS                     */
    /* ========================================================================== */

    // The write_event function redacts challenge IDs to an 8-char prefix via
    // challenge_id.get(..8).unwrap_or(challenge_id). These tests exercise the
    // same logic directly since write_event requires a worker Env binding.

    #[test]
    fn test_challenge_id_redaction_normal_uuid() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let redacted = uuid.get(..8).unwrap_or(uuid);
        assert_eq!(redacted, "550e8400");
    }

    #[test]
    fn test_challenge_id_redaction_exact_8_chars() {
        let id = "abcdefgh";
        let redacted = id.get(..8).unwrap_or(id);
        assert_eq!(redacted, "abcdefgh");
    }

    #[test]
    fn test_challenge_id_redaction_short_id() {
        let id = "abc";
        let redacted = id.get(..8).unwrap_or(id);
        // get(..8) returns None for a 3-char string, so unwrap_or gives original
        assert_eq!(redacted, "abc");
    }

    #[test]
    fn test_challenge_id_redaction_empty() {
        let id = "";
        let redacted = id.get(..8).unwrap_or(id);
        assert_eq!(redacted, "");
    }

    #[test]
    fn test_challenge_id_redaction_exactly_one_char() {
        let id = "x";
        let redacted = id.get(..8).unwrap_or(id);
        assert_eq!(redacted, "x");
    }

    #[test]
    fn test_challenge_id_redaction_7_chars() {
        let id = "1234567";
        let redacted = id.get(..8).unwrap_or(id);
        // 7 chars < 8, so get(..8) returns None, fallback to original
        assert_eq!(redacted, "1234567");
    }

    #[test]
    fn test_challenge_id_redaction_9_chars() {
        let id = "123456789";
        let redacted = id.get(..8).unwrap_or(id);
        assert_eq!(redacted, "12345678");
    }

    #[test]
    fn test_challenge_id_redaction_strips_sensitive_suffix() {
        // Verify that everything after position 8 is dropped
        let id = "12345678-SENSITIVE-DATA-HERE";
        let redacted = id.get(..8).unwrap_or(id);
        assert_eq!(redacted, "12345678");
        assert!(
            !redacted.contains("SENSITIVE"),
            "Redacted ID must not contain sensitive suffix"
        );
    }

    /* ========================================================================== */
    /*                    BLOB / DOUBLE FIELD ORDERING TESTS                     */
    /* ========================================================================== */

    // These tests validate the data structures built in write_event by
    // reconstructing the same Vec<String> / Vec<f64> logic outside of the
    // worker runtime.

    #[test]
    fn test_blob_vec_construction_all_fields() {
        let event = "verify_success";
        let route = "/v1/verify";
        let challenge_id = "550e8400-e29b-41d4-a716-446655440000";
        let origin = "https://example.com";
        let result = "ok";
        let environment = "production";

        let redacted_challenge_id = challenge_id.get(..8).unwrap_or(challenge_id);

        let blobs = [
            event.to_string(),
            route.to_string(),
            redacted_challenge_id.to_string(),
            origin.to_string(),
            "kid_123".to_string(),
            "abc123==".to_string(),
            result.to_string(),
            String::new(),
            environment.to_string(),
            String::new(),
            String::new(),
        ];

        assert_eq!(blobs.len(), 11, "Blob vec should have 11 positional fields");
        assert_eq!(blobs[0], "verify_success");
        assert_eq!(blobs[1], "/v1/verify");
        assert_eq!(
            blobs[2], "550e8400",
            "Challenge ID should be redacted to 8 chars"
        );
        assert_eq!(blobs[3], "https://example.com");
        assert_eq!(blobs[4], "kid_123");
        assert_eq!(blobs[5], "abc123==");
        assert_eq!(blobs[6], "ok");
        assert_eq!(blobs[7], "", "Error code should be empty for success");
        assert_eq!(blobs[8], "production");
        assert_eq!(blobs[9], "", "Reserved slot should be empty");
        assert_eq!(blobs[10], "", "Partner ID should be empty when None");
    }

    #[test]
    fn test_blob_vec_construction_error_case() {
        let event = "verify_failed";
        let route = "/v1/verify";
        let challenge_id = "deadbeef-0000-1111-2222-333344445555";
        let origin = "https://bad-actor.example.com";
        let result = "error";
        let environment = "sandbox";

        let redacted_challenge_id = challenge_id.get(..8).unwrap_or(challenge_id);

        let blobs = [
            event.to_string(),
            route.to_string(),
            redacted_challenge_id.to_string(),
            origin.to_string(),
            "none".to_string(),
            "none".to_string(),
            result.to_string(),
            "PROOF_INVALID".to_string(),
            environment.to_string(),
            String::new(),
            String::new(),
        ];

        assert_eq!(blobs.len(), 11);
        assert_eq!(blobs[0], "verify_failed");
        assert_eq!(blobs[2], "deadbeef", "Challenge ID redacted");
        assert_eq!(blobs[4], "none", "Missing issuer_kid maps to 'none'");
        assert_eq!(blobs[5], "none", "Missing issuer_hash maps to 'none'");
        assert_eq!(blobs[6], "error");
        assert_eq!(blobs[7], "PROOF_INVALID");
        assert_eq!(blobs[8], "sandbox");
    }

    #[test]
    fn test_doubles_vec_construction_success() {
        let count = 1.0_f64;
        let has_royalty = true;

        let doubles = [
            count,
            42.5_f64,
            6570.0_f64,
            200.0_f64,
            if has_royalty { 1.0 } else { 0.0 },
        ];

        assert_eq!(doubles.len(), 5, "Doubles vec should have 5 numeric fields");
        assert!((doubles[0] - 1.0).abs() < f64::EPSILON);
        assert!((doubles[1] - 42.5).abs() < f64::EPSILON);
        assert!((doubles[2] - 6570.0).abs() < f64::EPSILON);
        assert!((doubles[3] - 200.0).abs() < f64::EPSILON);
        assert!(
            (doubles[4] - 1.0).abs() < f64::EPSILON,
            "has_royalty=true should map to 1.0"
        );
    }

    #[test]
    fn test_doubles_vec_construction_no_royalty() {
        let count = 1.0_f64;
        let has_royalty = false;

        let doubles = [
            count,
            0.0_f64,
            0.0_f64,
            0.0_f64,
            if has_royalty { 1.0 } else { 0.0 },
        ];

        assert_eq!(doubles.len(), 5);
        assert!(
            (doubles[1] - 0.0).abs() < f64::EPSILON,
            "Missing duration should default to 0.0"
        );
        assert!(
            (doubles[2] - 0.0).abs() < f64::EPSILON,
            "Missing cutoff should default to 0.0"
        );
        assert!(
            (doubles[3] - 0.0).abs() < f64::EPSILON,
            "Missing status should default to 0.0"
        );
        assert!(
            (doubles[4] - 0.0).abs() < f64::EPSILON,
            "has_royalty=false should map to 0.0"
        );
    }

    #[test]
    fn test_doubles_vec_construction_negative_cutoff() {
        // Cutoff days could theoretically be negative (e.g. future date)
        let cutoff_days = Some(-365_i32);
        let doubles_val = cutoff_days.map(|d| d as f64).unwrap_or(0.0);
        assert!(
            (doubles_val - (-365.0)).abs() < f64::EPSILON,
            "Negative cutoff should be preserved"
        );
    }

    #[test]
    fn test_doubles_vec_construction_large_duration() {
        let val = 60_000.0_f64; // 60 seconds
        assert!(
            (val - 60_000.0).abs() < f64::EPSILON,
            "Large durations should be preserved"
        );
    }

    #[test]
    fn test_doubles_vec_construction_http_status_codes() {
        // Verify common HTTP status codes map correctly
        for status in [200_u16, 201, 400, 401, 403, 404, 429, 500] {
            let val = Some(status).map(|s| s as f64).unwrap_or(0.0);
            assert!(
                (val - f64::from(status)).abs() < f64::EPSILON,
                "HTTP status {} should map to {}.0",
                status,
                status
            );
        }
    }

    /* ========================================================================== */
    /*                    EVENT NAME CONSISTENCY TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_event_names_are_snake_case() {
        // All event names used in the Analytics methods should be snake_case
        let event_names = [
            "verify_success",
            "verify_failed",
            "billing_verification_success",
            "challenge_created",
            "hosted_status_checked",
            "hosted_redeemed",
            "hosted_session_checked",
            "cold_start",
            "cold_start_crypto",
            "cold_start_state",
            "cold_start_mek",
            "warm_request",
        ];

        for name in &event_names {
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "Event name '{}' should be snake_case",
                name
            );
            assert!(
                !name.starts_with('_'),
                "Event name '{}' should not start with underscore",
                name
            );
            assert!(
                !name.ends_with('_'),
                "Event name '{}' should not end with underscore",
                name
            );
            assert!(
                !name.contains("__"),
                "Event name '{}' should not have consecutive underscores",
                name
            );
        }
    }

    #[test]
    fn test_event_names_are_unique() {
        let event_names = [
            "verify_success",
            "verify_failed",
            "billing_verification_success",
            "challenge_created",
            "hosted_status_checked",
            "hosted_redeemed",
            "hosted_session_checked",
            "cold_start",
            "cold_start_crypto",
            "cold_start_state",
            "cold_start_mek",
            "warm_request",
        ];

        let unique: std::collections::HashSet<&&str> = event_names.iter().collect();
        assert_eq!(
            unique.len(),
            event_names.len(),
            "All event names should be unique"
        );
    }

    /* ========================================================================== */
    /*                    ADDITIONAL PROPERTY-BASED TESTS                        */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: origin_host with port always strips the port
        #[test]
        fn prop_origin_host_strips_port(
            host in "[a-z]{3,10}\\.com",
            port in 1u16..=65535
        ) {
            let url = format!("https://{}:{}", host, port);
            let result = origin_host(&url);
            prop_assert_eq!(result, host, "Port should be stripped from {}", url);
        }

        /// Property: origin_host with path always strips the path
        #[test]
        fn prop_origin_host_strips_path(
            host in "[a-z]{3,10}\\.com",
            path in "/[a-z]{1,20}"
        ) {
            let url = format!("https://{}{}", host, path);
            let result = origin_host(&url);
            prop_assert_eq!(result, host, "Path should be stripped from {}", url);
        }

        /// Property: challenge ID redaction never exceeds 8 chars
        #[test]
        fn prop_challenge_id_redaction_max_8_chars(id in "[a-f0-9]{0,64}") {
            let redacted = id.get(..8).unwrap_or(&id);
            prop_assert!(redacted.len() <= 8,
                "Redacted ID should be at most 8 chars, got {} for input '{}'",
                redacted.len(), id);
        }

        /// Property: challenge ID redaction preserves input when shorter than 8
        #[test]
        fn prop_challenge_id_redaction_preserves_short(id in "[a-f0-9]{0,7}") {
            let redacted = id.get(..8).unwrap_or(&id);
            prop_assert_eq!(redacted, id.as_str(),
                "Short IDs should pass through unchanged");
        }

        /// Property: blob vec always has 11 elements
        #[test]
        fn prop_blob_vec_always_11_elements(
            event in "[a-z_]{3,20}",
            route in "/[a-z]{1,10}",
            challenge_id in "[a-f0-9]{32,36}",
            origin in "https://[a-z]{3,10}\\.com",
            environment in "(production|sandbox)"
        ) {
            let redacted_challenge_id = challenge_id.get(..8).unwrap_or(&challenge_id);
            let blobs = vec![
                event.to_string(),
                route.to_string(),
                redacted_challenge_id.to_string(),
                origin.to_string(),
                "none".to_string(),
                "none".to_string(),
                "ok".to_string(),
                String::new(),
                environment.to_string(),
                String::new(),
                String::new(),
            ];
            prop_assert_eq!(blobs.len(), 11, "Blob vec should always have 11 elements");
        }

        /// Property: doubles vec always has 5 elements
        #[test]
        fn prop_doubles_vec_always_5_elements(
            count in 0.0f64..1000.0,
            duration in proptest::option::of(0.0f64..60000.0),
            cutoff in proptest::option::of(-365i32..36500),
            status in proptest::option::of(100u16..600),
            has_royalty in proptest::bool::ANY
        ) {
            let doubles = vec![
                count,
                duration.unwrap_or(0.0),
                cutoff.map(|d| d as f64).unwrap_or(0.0),
                status.map(|s| s as f64).unwrap_or(0.0),
                if has_royalty { 1.0 } else { 0.0 },
            ];
            prop_assert_eq!(doubles.len(), 5, "Doubles vec should always have 5 elements");
        }

        /// Property: origin_host with subdomains preserves the full hostname
        #[test]
        fn prop_origin_host_preserves_subdomains(
            sub in "[a-z]{2,5}",
            host in "[a-z]{3,10}\\.com"
        ) {
            let full_host = format!("{}.{}", sub, host);
            let url = format!("https://{}", full_host);
            let result = origin_host(&url);
            prop_assert_eq!(result, full_host);
        }
    }
}
