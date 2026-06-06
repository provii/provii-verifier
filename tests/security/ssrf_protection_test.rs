// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::string_slice
)]
//! SSRF Protection Integration Tests
//!
//! Comprehensive test suite for SSRF (Server-Side Request Forgery) protection.
//! Tests validate that private IPs, cloud metadata endpoints, and non-allowlisted
//! domains are blocked, while legitimate URLs pass validation.
//!
//! Reference: ASVS V1.3.6, V13.2.4
#![forbid(unsafe_code)]

use provii_verifier::utils::ssrf_protection::{
    validate_ip_address, validate_path_component, validate_url_for_fetch, SsrfConfig,
};
use std::net::IpAddr;
use wasm_bindgen_test::*;

/* ========================================================================== */
/*                    PRIVATE IP BLOCKING TESTS                              */
/* ========================================================================== */

#[wasm_bindgen_test]
fn test_block_rfc1918_10_0_0_0() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    // Test 10.0.0.0/8 range
    let ips = ["10.0.0.0", "10.0.0.1", "10.10.10.10", "10.255.255.255"];

    for ip_str in &ips {
        let ip: IpAddr = ip_str.parse()?;
        let result = validate_ip_address(&ip, &config);
        assert!(
            result.is_err(),
            "Private IP {} should be blocked (RFC 1918 10.x.x.x)",
            ip_str
        );
        assert_eq!(
            result.err().ok_or("expected error")?.to_string(),
            "forbidden",
            "Private IP {} should produce Forbidden error",
            ip_str
        );
    }
    Ok(())
}

#[wasm_bindgen_test]
fn test_block_rfc1918_172_16_0_0() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    // Test 172.16.0.0/12 range
    let ips = ["172.16.0.0", "172.16.0.1", "172.31.255.255"];

    for ip_str in &ips {
        let ip: IpAddr = ip_str.parse()?;
        let result = validate_ip_address(&ip, &config);
        assert!(
            result.is_err(),
            "Private IP {} should be blocked (RFC 1918 172.16.x.x-172.31.x.x)",
            ip_str
        );
    }
    Ok(())
}

#[wasm_bindgen_test]
fn test_block_rfc1918_192_168_0_0() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    // Test 192.168.0.0/16 range
    let ips = [
        "192.168.0.0",
        "192.168.0.1",
        "192.168.1.1",
        "192.168.255.255",
    ];

    for ip_str in &ips {
        let ip: IpAddr = ip_str.parse()?;
        let result = validate_ip_address(&ip, &config);
        assert!(
            result.is_err(),
            "Private IP {} should be blocked (RFC 1918 192.168.x.x)",
            ip_str
        );
    }
    Ok(())
}

/* ========================================================================== */
/*                    LOOPBACK BLOCKING TESTS                                */
/* ========================================================================== */

#[wasm_bindgen_test]
fn test_block_loopback_127_0_0_1() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();
    let ip: IpAddr = "127.0.0.1".parse()?;
    let result = validate_ip_address(&ip, &config);

    assert!(result.is_err(), "127.0.0.1 must be blocked as loopback");
    assert_eq!(
        result.err().ok_or("expected error")?.to_string(),
        "forbidden"
    );
    Ok(())
}

#[wasm_bindgen_test]
fn test_block_loopback_range() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    // Entire 127.0.0.0/8 range should be blocked
    let ips = [
        "127.0.0.0",
        "127.0.0.1",
        "127.1.1.1",
        "127.255.255.254",
        "127.255.255.255",
    ];

    for ip_str in &ips {
        let ip: IpAddr = ip_str.parse()?;
        let result = validate_ip_address(&ip, &config);
        assert!(
            result.is_err(),
            "Loopback IP {} should be blocked (127.x.x.x range)",
            ip_str
        );
    }
    Ok(())
}

#[wasm_bindgen_test]
fn test_block_ipv6_loopback() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();
    let ip: IpAddr = "::1".parse()?;
    let result = validate_ip_address(&ip, &config);

    assert!(result.is_err(), "::1 must be blocked as IPv6 loopback");
    assert_eq!(
        result.err().ok_or("expected error")?.to_string(),
        "forbidden"
    );
    Ok(())
}

/* ========================================================================== */
/*                    LINK-LOCAL BLOCKING TESTS                              */
/* ========================================================================== */

#[wasm_bindgen_test]
fn test_block_link_local_169_254() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    // Test 169.254.0.0/16 range
    let ips = [
        "169.254.0.0",
        "169.254.0.1",
        "169.254.1.1",
        "169.254.255.255",
    ];

    for ip_str in &ips {
        let ip: IpAddr = ip_str.parse()?;
        let result = validate_ip_address(&ip, &config);
        assert!(
            result.is_err(),
            "Link-local IP {} should be blocked (169.254.x.x)",
            ip_str
        );
        assert_eq!(
            result.err().ok_or("expected error")?.to_string(),
            "forbidden",
            "Link-local IP {} should produce Forbidden error",
            ip_str
        );
    }
    Ok(())
}

#[wasm_bindgen_test]
fn test_block_ipv6_link_local() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    let ips = ["fe80::1", "fe80::dead:beef", "fe80::ffff:ffff:ffff:ffff"];

    for ip_str in &ips {
        let ip: IpAddr = ip_str.parse()?;
        let result = validate_ip_address(&ip, &config);
        assert!(
            result.is_err(),
            "IPv6 link-local {} should be blocked (fe80::/10)",
            ip_str
        );
        assert_eq!(
            result.err().ok_or("expected error")?.to_string(),
            "forbidden",
            "IPv6 link-local {} should produce Forbidden error",
            ip_str
        );
    }
    Ok(())
}

/* ========================================================================== */
/*                    CLOUD METADATA BLOCKING TESTS                          */
/* ========================================================================== */

#[wasm_bindgen_test]
fn test_block_cloud_metadata_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    // AWS/GCP/Azure cloud metadata endpoint
    let ip: IpAddr = "169.254.169.254".parse()?;
    let result = validate_ip_address(&ip, &config);

    assert!(
        result.is_err(),
        "169.254.169.254 must be blocked as cloud metadata"
    );
    assert_eq!(
        result.err().ok_or("expected error")?.to_string(),
        "forbidden"
    );
    Ok(())
}

#[wasm_bindgen_test]
fn test_block_cloud_metadata_url() {
    let config = SsrfConfig::default();

    // Test common cloud metadata URLs
    let urls = [
        "https://169.254.169.254/latest/meta-data",
        "https://169.254.169.254/metadata/instance",
        "https://169.254.169.254/computeMetadata/v1",
    ];

    for url in &urls {
        let result = validate_url_for_fetch(url, &config);
        assert!(
            result.is_err(),
            "Cloud metadata URL {} should be blocked",
            url
        );
    }
}

/* ========================================================================== */
/*                    ALLOWLIST VALIDATION TESTS                             */
/* ========================================================================== */

#[wasm_bindgen_test]
fn test_allowlist_exact_match() {
    let config = SsrfConfig::new(vec!["cdn.provii.app".to_string()]);

    let result = validate_url_for_fetch("https://cdn.provii.app/v1/jwks.json", &config);
    assert!(result.is_ok(), "Exact match should be allowed");
}

#[wasm_bindgen_test]
fn test_allowlist_wildcard_subdomain() {
    let config = SsrfConfig::new(vec!["*.provii.app".to_string()]);

    // Should match any subdomain
    let urls = [
        "https://cdn.provii.app/test",
        "https://api.provii.app/test",
        "https://foo.provii.app/test",
    ];

    for url in &urls {
        let result = validate_url_for_fetch(url, &config);
        assert!(result.is_ok(), "Wildcard should match {}", url);
    }
}

#[wasm_bindgen_test]
fn test_allowlist_blocks_non_listed_domains() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::new(vec!["cdn.provii.app".to_string()]);

    let urls = [
        "https://evil.com/malicious",
        "https://attacker.example.com/ssrf",
        "https://malicious-cdn.provii.app.evil.com/test",
    ];

    for url in &urls {
        let result = validate_url_for_fetch(url, &config);
        assert!(
            result.is_err(),
            "Non-allowlisted domain {} should be blocked",
            url
        );
        assert_eq!(
            result.err().ok_or("expected error")?.to_string(),
            "forbidden",
            "Non-allowlisted domain {} should produce Forbidden error",
            url
        );
    }
    Ok(())
}

#[wasm_bindgen_test]
fn test_allowlist_multiple_domains() {
    let config = SsrfConfig::new(vec![
        "cdn.provii.app".to_string(),
        "api.example.com".to_string(),
        "*.cloudflare.com".to_string(),
    ]);

    // Should allow all listed domains
    let allowed_urls = [
        "https://cdn.provii.app/test",
        "https://api.example.com/test",
        "https://workers.cloudflare.com/test",
    ];

    for url in &allowed_urls {
        let result = validate_url_for_fetch(url, &config);
        assert!(result.is_ok(), "Allowlisted domain {} should pass", url);
    }

    // Should block non-listed
    let blocked = validate_url_for_fetch("https://evil.com/test", &config);
    assert!(blocked.is_err());
}

/* ========================================================================== */
/*                    LEGITIMATE URL TESTS                                   */
/* ========================================================================== */

#[wasm_bindgen_test]
fn test_legitimate_jwks_url_passes() {
    let config = SsrfConfig::default();

    let result = validate_url_for_fetch("https://cdn.provii.app/v1/jwks.json", &config);
    assert!(result.is_ok(), "Legitimate JWKS URL should pass");
}

#[wasm_bindgen_test]
fn test_legitimate_public_ips() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    // Public IPs that should be allowed (but blocked by allowlist)
    let public_ips = [
        "8.8.8.8",        // Google DNS
        "1.1.1.1",        // Cloudflare DNS
        "13.107.42.14",   // Microsoft
        "142.250.185.46", // Google
    ];

    for ip_str in &public_ips {
        let ip: IpAddr = ip_str.parse()?;
        let result = validate_ip_address(&ip, &config);
        // Public IPs should pass IP validation (not in private ranges)
        assert!(
            result.is_ok(),
            "Public IP {} should pass IP validation",
            ip_str
        );
    }
    Ok(())
}

/* ========================================================================== */
/*                    HTTPS ENFORCEMENT TESTS                                */
/* ========================================================================== */

#[wasm_bindgen_test]
fn test_block_http_urls() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    let http_urls = [
        "http://cdn.provii.app/test",
        "http://localhost/test",
        "http://example.com/test",
    ];

    for url in &http_urls {
        let result = validate_url_for_fetch(url, &config);
        assert!(result.is_err(), "HTTP URL {} should be blocked", url);
        assert_eq!(
            result.err().ok_or("expected error")?.to_string(),
            "bad-request",
            "HTTP URL {} should produce BadRequest error",
            url
        );
    }
    Ok(())
}

#[wasm_bindgen_test]
fn test_block_ftp_urls() {
    let config = SsrfConfig::default();
    let result = validate_url_for_fetch("ftp://example.com/file", &config);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn test_block_file_urls() {
    let config = SsrfConfig::default();
    let result = validate_url_for_fetch("file:///etc/passwd", &config);
    assert!(result.is_err());
}

/* ========================================================================== */
/*                    DNS REBINDING PREVENTION TESTS                         */
/* ========================================================================== */

#[wasm_bindgen_test]
fn test_direct_ip_bypasses_hostname_allowlist() {
    let config = SsrfConfig::new(vec!["cdn.provii.app".to_string()]);

    // Even if using a direct IP, it should be validated
    // This prevents DNS rebinding where domain resolves to different IP later
    let result = validate_url_for_fetch("https://192.168.1.1/test", &config);
    assert!(
        result.is_err(),
        "Direct private IP should be blocked even with hostname allowlist"
    );
}

/* ========================================================================== */
/*                    URL ENCODING BYPASS PREVENTION TESTS                   */
/* ========================================================================== */

#[wasm_bindgen_test]
fn test_prevent_url_encoding_bypass() {
    let config = SsrfConfig::default();

    // Attempts to bypass with URL encoding
    let bypass_attempts = [
        "https://127.0.0.1%2F@evil.com/test",
        "https://127.0.0.1%23@evil.com/test",
    ];

    for url in &bypass_attempts {
        let result = validate_url_for_fetch(url, &config);
        // Should fail either in parsing or validation
        assert!(result.is_err(), "URL encoding bypass {} should fail", url);
    }
}

/* ========================================================================== */
/*                    IPV6 UNIQUE LOCAL ADDRESS TESTS                        */
/* ========================================================================== */

#[wasm_bindgen_test]
fn test_block_ipv6_unique_local_addresses() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    // IPv6 ULA (Unique Local Addresses) fc00::/7
    let ulas = ["fc00::1", "fd00::1", "fd12:3456:789a:1::1"];

    for ip_str in &ulas {
        let ip: IpAddr = ip_str.parse()?;
        let result = validate_ip_address(&ip, &config);
        assert!(
            result.is_err(),
            "IPv6 ULA {} should be blocked (fc00::/7)",
            ip_str
        );
        assert_eq!(
            result.err().ok_or("expected error")?.to_string(),
            "forbidden",
            "IPv6 ULA {} should produce Forbidden error",
            ip_str
        );
    }
    Ok(())
}

/* ========================================================================== */
/*                    CONFIG FROM ENVIRONMENT TESTS                          */
/* ========================================================================== */

#[wasm_bindgen_test]
fn test_ssrf_config_from_env_parses_correctly() {
    let env_var = Some("cdn.provii.app,api.example.com,*.cloudflare.com".to_string());
    let config = SsrfConfig::from_env(env_var);

    assert_eq!(config.allowed_hosts.len(), 3);
    assert!(config.allowed_hosts.contains(&"cdn.provii.app".to_string()));
    assert!(config
        .allowed_hosts
        .contains(&"api.example.com".to_string()));
    assert!(config
        .allowed_hosts
        .contains(&"*.cloudflare.com".to_string()));
}

#[wasm_bindgen_test]
fn test_ssrf_config_from_env_handles_whitespace() {
    let env_var = Some("  cdn.provii.app  ,  api.example.com  ".to_string());
    let config = SsrfConfig::from_env(env_var);

    assert_eq!(config.allowed_hosts.len(), 2);
    // Whitespace should be trimmed
    assert!(config.allowed_hosts.contains(&"cdn.provii.app".to_string()));
    assert!(config
        .allowed_hosts
        .contains(&"api.example.com".to_string()));
}

#[wasm_bindgen_test]
fn test_ssrf_config_from_env_empty_fallback() {
    let config = SsrfConfig::from_env(None);

    // Should fall back to default
    assert_eq!(config.allowed_hosts.len(), 1);
    assert_eq!(config.allowed_hosts[0], "cdn.provii.app");
}

/* ========================================================================== */
/*                    EDGE CASE TESTS                                        */
/* ========================================================================== */

#[wasm_bindgen_test]
fn test_invalid_url_format() {
    let config = SsrfConfig::default();

    let invalid_urls = ["not a url", "://missing-scheme", "https://", ""];

    for url in &invalid_urls {
        let result = validate_url_for_fetch(url, &config);
        assert!(result.is_err(), "Invalid URL {} should be rejected", url);
    }
}

#[wasm_bindgen_test]
fn test_url_with_port() {
    let config = SsrfConfig::new(vec!["cdn.provii.app".to_string()]);

    // URL with port should still work
    let result = validate_url_for_fetch("https://cdn.provii.app:443/test", &config);
    assert!(result.is_ok(), "URL with standard HTTPS port should work");
}

#[wasm_bindgen_test]
fn test_url_with_query_params() {
    let config = SsrfConfig::new(vec!["cdn.provii.app".to_string()]);

    let result = validate_url_for_fetch("https://cdn.provii.app/test?version=1&key=value", &config);
    assert!(result.is_ok(), "URL with query params should work");
}

#[wasm_bindgen_test]
fn test_url_with_fragment() {
    let config = SsrfConfig::new(vec!["cdn.provii.app".to_string()]);

    let result = validate_url_for_fetch("https://cdn.provii.app/test#section", &config);
    assert!(result.is_ok(), "URL with fragment should work");
}

/* ========================================================================== */
/*                    FULL ATTACK VECTOR TESTS                               */
/* ========================================================================== */

#[wasm_bindgen_test]
fn test_full_private_network_blocking() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    // Test full list of private/special IPs that should be blocked
    let blocked_ips = [
        // RFC 1918
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        // Loopback
        "127.0.0.1",
        "127.255.255.255",
        // Link-local
        "169.254.1.1",
        "169.254.169.254",
        // IPv6 special
        "::1",
        "fe80::1",
        "fc00::1",
        "fd00::1",
    ];

    for ip_str in &blocked_ips {
        let ip: IpAddr = ip_str.parse()?;
        let result = validate_ip_address(&ip, &config);
        assert!(
            result.is_err(),
            "Special/private IP {} should be blocked",
            ip_str
        );
    }
    Ok(())
}

#[wasm_bindgen_test]
fn test_full_legitimate_hosts() {
    let config = SsrfConfig::new(vec![
        "cdn.provii.app".to_string(),
        "*.cloudflare.com".to_string(),
    ]);

    let legitimate_urls = [
        "https://cdn.provii.app/v1/jwks.json",
        "https://cdn.provii.app/v1/crl.json",
        "https://workers.cloudflare.com/api",
    ];

    for url in &legitimate_urls {
        let result = validate_url_for_fetch(url, &config);
        assert!(result.is_ok(), "Legitimate URL {} should pass", url);
    }
}

/* ========================================================================== */
/*                    ATTACK VECTOR COVERAGE TESTS                           */
/*                                                                           */
/*  18 test cases covering gaps identified in SSRF test coverage audit.      */
/*  Reference: SSRF Fix Plan T-10                                            */
/* ========================================================================== */

// -----------------------------------------------------------------------
// 1. IPv4-mapped IPv6 addresses (SSRF-002)
//
// An attacker can embed IPv4 addresses inside IPv6 notation to bypass
// naive IPv4-only checks. The SSRF module extracts the embedded IPv4
// via Ipv6Addr::to_ipv4_mapped() and re-validates it.
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_block_ipv4_mapped_ipv6_loopback() -> Result<(), Box<dyn std::error::Error>> {
    // ::ffff:127.0.0.1 embeds the IPv4 loopback inside IPv6 notation.
    let config = SsrfConfig::default();
    let ip: IpAddr = "::ffff:127.0.0.1".parse()?;
    let result = validate_ip_address(&ip, &config);
    assert!(
        result.is_err(),
        "IPv4-mapped IPv6 loopback ::ffff:127.0.0.1 must be blocked"
    );
    Ok(())
}

#[wasm_bindgen_test]
fn test_block_ipv4_mapped_ipv6_private() -> Result<(), Box<dyn std::error::Error>> {
    // ::ffff:10.0.0.1 embeds RFC 1918 private address.
    let config = SsrfConfig::default();
    let ip: IpAddr = "::ffff:10.0.0.1".parse()?;
    let result = validate_ip_address(&ip, &config);
    assert!(
        result.is_err(),
        "IPv4-mapped IPv6 private ::ffff:10.0.0.1 must be blocked"
    );
    Ok(())
}

#[wasm_bindgen_test]
fn test_block_ipv4_mapped_ipv6_metadata() -> Result<(), Box<dyn std::error::Error>> {
    // ::ffff:169.254.169.254 embeds cloud metadata endpoint.
    let config = SsrfConfig::default();
    let ip: IpAddr = "::ffff:169.254.169.254".parse()?;
    let result = validate_ip_address(&ip, &config);
    assert!(
        result.is_err(),
        "IPv4-mapped IPv6 metadata ::ffff:169.254.169.254 must be blocked"
    );
    Ok(())
}

// -----------------------------------------------------------------------
// 2. "This" network: 0.0.0.0/8 (SSRF-007)
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_block_zero_address() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    // 0.0.0.0 ("this host on this network", RFC 1122)
    let ip: IpAddr = "0.0.0.0".parse()?;
    let result = validate_ip_address(&ip, &config);
    assert!(result.is_err(), "0.0.0.0 must be blocked");

    // 0.1.2.3 (within 0.0.0.0/8)
    let ip2: IpAddr = "0.1.2.3".parse()?;
    let result2 = validate_ip_address(&ip2, &config);
    assert!(result2.is_err(), "0.1.2.3 (0.x.x.x range) must be blocked");
    Ok(())
}

// -----------------------------------------------------------------------
// 3. Broadcast address: 255.255.255.255 (SSRF-007)
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_block_broadcast_address() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();
    let ip: IpAddr = "255.255.255.255".parse()?;
    let result = validate_ip_address(&ip, &config);
    assert!(
        result.is_err(),
        "Broadcast address 255.255.255.255 must be blocked"
    );
    Ok(())
}

// -----------------------------------------------------------------------
// 4. CGNAT range: 100.64.0.0/10 (SSRF-006)
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_block_cgnat_range() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    // Bottom of range
    let ip1: IpAddr = "100.64.0.1".parse()?;
    assert!(
        validate_ip_address(&ip1, &config).is_err(),
        "CGNAT 100.64.0.1 must be blocked"
    );

    // Top of range
    let ip2: IpAddr = "100.127.255.254".parse()?;
    assert!(
        validate_ip_address(&ip2, &config).is_err(),
        "CGNAT 100.127.255.254 must be blocked"
    );
    Ok(())
}

// -----------------------------------------------------------------------
// 5. IPv6 multicast: ff00::/8 (SSRF-008)
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_block_ipv6_multicast() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();

    let multicast_addrs = ["ff00::1", "ff02::1"];
    for ip_str in &multicast_addrs {
        let ip: IpAddr = ip_str.parse()?;
        let result = validate_ip_address(&ip, &config);
        assert!(result.is_err(), "IPv6 multicast {} must be blocked", ip_str);
    }
    Ok(())
}

// -----------------------------------------------------------------------
// 6. IPv6 unspecified: :: (SSRF-008)
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_block_ipv6_unspecified() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();
    let ip: IpAddr = "::".parse()?;
    let result = validate_ip_address(&ip, &config);
    assert!(
        result.is_err(),
        "IPv6 unspecified address :: must be blocked"
    );
    Ok(())
}

// -----------------------------------------------------------------------
// 7. IPv6 documentation range: 2001:db8::/32 (SSRF-008)
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_block_ipv6_documentation() -> Result<(), Box<dyn std::error::Error>> {
    let config = SsrfConfig::default();
    let ip: IpAddr = "2001:db8::1".parse()?;
    let result = validate_ip_address(&ip, &config);
    assert!(
        result.is_err(),
        "IPv6 documentation address 2001:db8::1 must be blocked"
    );
    Ok(())
}

// -----------------------------------------------------------------------
// 8. Wildcard suffix bypass (SSRF-003)
//
// "evilprovii.app" must NOT match *.provii.app. The
// wildcard pattern requires a dot-separated subdomain boundary.
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_wildcard_suffix_bypass_rejected() {
    let config = SsrfConfig::new(vec!["*.provii.app".to_string()]);

    // "evilprovii.app" shares a suffix but is NOT a subdomain
    let result = validate_url_for_fetch("https://evilprovii.app/steal", &config);
    assert!(
        result.is_err(),
        "evilprovii.app must NOT match *.provii.app"
    );
}

// -----------------------------------------------------------------------
// 9. Non-standard port rejection (SSRF-009)
//
// Only port 443 (or default/omitted) is allowed. Any other port,
// even on an allowlisted host, must be rejected.
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_block_non_standard_port() {
    let config = SsrfConfig::new(vec!["cdn.provii.app".to_string()]);

    let result = validate_url_for_fetch("https://cdn.provii.app:8443/test", &config);
    assert!(
        result.is_err(),
        "Non-standard port 8443 on allowlisted host must be rejected"
    );
}

// -----------------------------------------------------------------------
// 10. javascript: and data: scheme rejection (SSRF-001)
//
// Only HTTPS is allowed. Exotic schemes used in XSS payloads must be
// caught by the scheme check.
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_block_javascript_scheme() {
    let config = SsrfConfig::default();
    let result = validate_url_for_fetch("javascript:alert(1)", &config);
    assert!(result.is_err(), "javascript: scheme must be rejected");
}

#[wasm_bindgen_test]
fn test_block_data_scheme() {
    let config = SsrfConfig::default();
    let result = validate_url_for_fetch("data:text/html,<h1>ssrf</h1>", &config);
    assert!(result.is_err(), "data: scheme must be rejected");
}

// -----------------------------------------------------------------------
// 11. URL userinfo (credentials in URL)
//
// The url crate (WHATWG spec) strips userinfo from host_str(), so the
// host validation still applies correctly. The allowlisted host is
// extracted regardless of embedded credentials.
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_userinfo_does_not_bypass_allowlist() {
    // Allowlisted host with userinfo should still pass host validation
    // because the url crate extracts the host without the userinfo.
    let config = SsrfConfig::new(vec!["cdn.provii.app".to_string()]);
    let result = validate_url_for_fetch("https://user:pass@cdn.provii.app/test", &config);
    assert!(
        result.is_ok(),
        "Userinfo should not break host extraction for allowlisted domain"
    );

    // Non-allowlisted host with userinfo must still be rejected.
    let result2 = validate_url_for_fetch("https://user:pass@evil.com/test", &config);
    assert!(
        result2.is_err(),
        "Userinfo on non-allowlisted host must still be rejected"
    );
}

// -----------------------------------------------------------------------
// 12. Double encoding (%252e%252e in path components)
//
// validate_path_component rejects any value containing '%', which
// catches both single-encoded and double-encoded sequences.
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_double_encoding_in_path_component() {
    // %252e decodes to %2e at the first layer, then to '.' at the
    // second. The '%' character itself triggers rejection.
    let result = validate_path_component("%252e%252e", "kid");
    assert!(
        result.is_err(),
        "Double-encoded traversal %252e%252e must be rejected"
    );

    // Single-encoded dot is also rejected (contains '%')
    let result2 = validate_path_component("%2e%2e", "kid");
    assert!(
        result2.is_err(),
        "Single-encoded traversal %2e%2e must be rejected"
    );
}

// -----------------------------------------------------------------------
// 13. Null bytes (%00) in path components
//
// Null bytes can truncate strings in some backends. The '%' character
// triggers rejection in validate_path_component. The raw null byte
// (control character) is caught by the is_control() check.
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_null_byte_in_path_component() {
    // Percent-encoded null byte
    let result = validate_path_component("issuer%00evil", "kid");
    assert!(
        result.is_err(),
        "Percent-encoded null byte must be rejected"
    );

    // Raw null byte (control character)
    let result2 = validate_path_component("issuer\x00evil", "kid");
    assert!(
        result2.is_err(),
        "Raw null byte must be rejected as control character"
    );
}

// -----------------------------------------------------------------------
// 14. Octal and hexadecimal IP notation
//
// Attackers use alternative IP representations to bypass naive string
// matching. The WHATWG URL parser (url crate) normalises these to
// standard dotted-decimal IPv4, so the SSRF IP validation catches them.
//
// 0x7f000001 = 127.0.0.1 (hex)
// 0177.0.0.1 = 127.0.0.1 (leading-zero octal)
// 2130706433 = 127.0.0.1 (decimal integer)
// -----------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_block_hex_ip_notation_in_url() {
    let config = SsrfConfig::default();

    // The url crate normalises 0x7f000001 to 127.0.0.1. The loopback
    // check then blocks it.
    let result = validate_url_for_fetch("https://0x7f000001/path", &config);
    assert!(
        result.is_err(),
        "Hex IP notation 0x7f000001 (127.0.0.1) must be blocked"
    );
}

#[wasm_bindgen_test]
fn test_block_octal_ip_notation_in_url() {
    let config = SsrfConfig::default();

    // 0177.0.0.1 is normalised to 127.0.0.1 by the WHATWG URL parser.
    let result = validate_url_for_fetch("https://0177.0.0.1/path", &config);
    assert!(
        result.is_err(),
        "Octal IP notation 0177.0.0.1 (127.0.0.1) must be blocked"
    );
}

#[wasm_bindgen_test]
fn test_block_decimal_integer_ip_in_url() {
    let config = SsrfConfig::default();

    // 2130706433 = 0x7F000001 = 127.0.0.1 in decimal integer notation.
    let result = validate_url_for_fetch("https://2130706433/path", &config);
    assert!(
        result.is_err(),
        "Decimal integer IP 2130706433 (127.0.0.1) must be blocked"
    );
}
