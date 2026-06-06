// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! SSRF (Server-Side Request Forgery) Protection Module
//!
//! Validates URLs before outbound fetches to prevent SSRF attacks. Checks cover:
//!
//! - HTTPS enforcement
//! - Port restriction (443 only)
//! - Private IP ranges (RFC 1918)
//! - Loopback addresses (127.0.0.0/8, ::1)
//! - Link-local addresses (169.254.0.0/16, fe80::/10)
//! - CGNAT addresses (100.64.0.0/10)
//! - "This" network (0.0.0.0/8)
//! - Multicast (224.0.0.0/4, ff00::/8)
//! - Reserved (240.0.0.0/4)
//! - RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
//! - Benchmarking range (198.18.0.0/15)
//! - IPv6 documentation (2001:db8::/32)
//! - IPv4-mapped IPv6 re-validation
//! - Cloud metadata endpoints (IP and hostname based)
//! - Hostname blocklist (localhost, .local, .internal, .localhost)
//! - Configurable domain allowlist with wildcard support
//!
//! Reference: ASVS V1.3.6, V13.2.4, V13.2.6
//! Security Control: Critical
#![forbid(unsafe_code)]

use crate::error::{ApiError, ApiResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Private IPv4 ranges as defined by RFC 1918.
const PRIVATE_IPV4_RANGES: &[(u32, u32)] = &[
    (0x0A000000, 0x0AFFFFFF), // 10.0.0.0/8
    (0xAC100000, 0xAC1FFFFF), // 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF), // 192.168.0.0/16
];

/// Loopback range: 127.0.0.0/8
const LOOPBACK_IPV4_START: u32 = 0x7F000000;
const LOOPBACK_IPV4_END: u32 = 0x7FFFFFFF;

/// Link-local range: 169.254.0.0/16
const LINK_LOCAL_IPV4_START: u32 = 0xA9FE0000;
const LINK_LOCAL_IPV4_END: u32 = 0xA9FEFFFF;

/// Cloud metadata endpoint (AWS, GCP, Azure): 169.254.169.254
const CLOUD_METADATA_IP: u32 = 0xA9FEA9FE;

/// CGNAT range: 100.64.0.0/10 (RFC 6598)
const CGNAT_IPV4_START: u32 = 0x64400000; // 100.64.0.0
const CGNAT_IPV4_END: u32 = 0x647FFFFF; // 100.127.255.255

/// "This" network: 0.0.0.0/8
const THIS_NET_IPV4_START: u32 = 0x00000000;
const THIS_NET_IPV4_END: u32 = 0x00FFFFFF;

/// RFC 5737 documentation ranges
const DOC_IPV4_RANGES: &[(u32, u32)] = &[
    (0xC0000200, 0xC00002FF), // 192.0.2.0/24 (TEST-NET-1)
    (0xC6336400, 0xC63364FF), // 198.51.100.0/24 (TEST-NET-2)
    (0xCB007100, 0xCB0071FF), // 203.0.113.0/24 (TEST-NET-3)
];

/// Benchmarking range: 198.18.0.0/15
const BENCH_IPV4_START: u32 = 0xC6120000; // 198.18.0.0
const BENCH_IPV4_END: u32 = 0xC613FFFF; // 198.19.255.255

/// Blocked hostnames for defence in depth.
const BLOCKED_HOSTNAMES: &[&str] = &["localhost", "localhost.localdomain"];

/// Blocked hostname suffixes. Each entry is checked with an exact match
/// for the bare label (e.g. "local") or as a dot-prefixed suffix
/// (e.g. ".local").
const BLOCKED_HOSTNAME_SUFFIXES: &[&str] = &[".local", ".internal", ".localhost"];

/// Cloud metadata hostnames blocked regardless of allowlist.
const METADATA_HOSTNAMES: &[&str] = &["metadata.google.internal", "metadata.goog", "metadata"];

/// SSRF protection configuration.
#[derive(Debug, Clone)]
pub struct SsrfConfig {
    /// Allowed domains/hosts (e.g. `["cdn.provii.app"]`).
    pub allowed_hosts: Vec<String>,
    /// Allow localhost/loopback for testing (DANGEROUS).
    pub allow_loopback: bool,
    /// Allow private IPs for testing (DANGEROUS).
    pub allow_private_ips: bool,
}

impl Default for SsrfConfig {
    fn default() -> Self {
        Self {
            allowed_hosts: vec!["cdn.provii.app".to_string()],
            allow_loopback: false,
            allow_private_ips: false,
        }
    }
}

impl SsrfConfig {
    /// Create a config with specified allowed hosts.
    pub fn new(allowed_hosts: Vec<String>) -> Self {
        Self {
            allowed_hosts,
            allow_loopback: false,
            allow_private_ips: false,
        }
    }

    /// Create a production-safe config from an optional environment variable.
    ///
    /// Expects a comma-separated list of allowed hosts.
    /// Falls back to default (`cdn.provii.app`) if not set.
    pub fn from_env(env_var: Option<String>) -> Self {
        let allowed_hosts = env_var
            .map(|s| {
                s.split(',')
                    .map(|host| host.trim().to_string())
                    .filter(|host| !host.is_empty())
                    .collect()
            })
            .unwrap_or_else(|| vec!["cdn.provii.app".to_string()]);

        Self {
            allowed_hosts,
            allow_loopback: false,
            allow_private_ips: false,
        }
    }
}

/// Validate a URL for SSRF protection before fetching.
///
/// This function performs full SSRF validation:
/// 1. Parse URL and enforce HTTPS scheme
/// 2. SSRF-009: Enforce port 443 (or default)
/// 3. Check hostname against blocklist and metadata endpoints
/// 4. Check hostname against allowlist
/// 5. If hostname is an IP address, validate against all restricted ranges
///
/// # Arguments
/// * `url` - The URL to validate
/// * `config` - SSRF protection configuration
///
/// # Returns
/// * `Ok(())` if URL passes all SSRF checks
/// * `Err(ApiError)` if URL is blocked
///
/// # Security
/// This is a critical security control. In Cloudflare Workers DNS resolution
/// is not directly available, so we rely on the hostname allowlist as the
/// primary defence. IP-literal URLs are validated against all restricted
/// ranges including IPv4-mapped IPv6 addresses.
pub fn validate_url_for_fetch(url: &str, config: &SsrfConfig) -> ApiResult<()> {
    let parsed_url = url::Url::parse(url).map_err(|e| {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] Invalid URL format: {}", e);
        ApiError::BadRequest(Some(format!("Invalid URL format: {}", e)))
    })?;

    // SSRF-001: HTTPS only
    if parsed_url.scheme() != "https" {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] Non-HTTPS scheme blocked: {}", parsed_url.scheme());
        return Err(ApiError::BadRequest(Some(
            "Only HTTPS URLs are allowed for security".to_string(),
        )));
    }

    // SSRF-009: Port restriction. Only port 443 or the default (no explicit port).
    match parsed_url.port() {
        None | Some(443) => {}
        Some(_port) => {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[SSRF] Non-standard _port blocked: {}", _port);
            return Err(ApiError::BadRequest(Some(
                "Only port 443 is allowed".to_string(),
            )));
        }
    }

    let hostname = parsed_url.host_str().ok_or_else(|| {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] URL has no hostname");
        ApiError::BadRequest(Some("URL must have a hostname".to_string()))
    })?;

    // SSRF-012: Hostname blocklist
    validate_hostname_not_blocked(hostname)?;

    // SSRF-024: Metadata hostname blocklist
    validate_hostname_not_metadata(hostname)?;

    // Allowlist check
    validate_hostname_allowlist(hostname, config)?;

    // IP literal validation (covers IPv4, IPv6, and IPv4-mapped IPv6)
    let host_clean = hostname.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host_clean.parse::<IpAddr>() {
        validate_ip_address(&ip, config)?;
    }

    Ok(())
}

/// Validate a URL specifically for outbound client requests.
///
/// This performs a subset of SSRF checks appropriate for base URLs
/// configured via environment variables (provii-issuer, provii-credit-management).
/// These are trusted URLs set by operators, so we enforce scheme and port
/// restrictions but skip the allowlist (the base URL itself is the trust
/// anchor).
///
/// SSRF-070: Enforce HTTPS scheme on base URLs.
/// SSRF-009: Enforce port 443.
/// SSRF-012: Block dangerous hostnames.
pub fn validate_base_url(url: &str) -> ApiResult<()> {
    let parsed = url::Url::parse(url)
        .map_err(|e| ApiError::BadRequest(Some(format!("Invalid base URL: {}", e))))?;

    if parsed.scheme() != "https" {
        return Err(ApiError::BadRequest(Some(
            "Base URL must use HTTPS".to_string(),
        )));
    }

    match parsed.port() {
        None | Some(443) => {}
        Some(port) => {
            return Err(ApiError::BadRequest(Some(format!(
                "Base URL port {} is not allowed, only 443",
                port
            ))));
        }
    }

    if let Some(hostname) = parsed.host_str() {
        validate_hostname_not_blocked(hostname)?;
        validate_hostname_not_metadata(hostname)?;

        let host_clean = hostname.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host_clean.parse::<IpAddr>() {
            // Use a strict config: no loopback, no private IPs.
            let strict = SsrfConfig {
                allowed_hosts: vec![],
                allow_loopback: false,
                allow_private_ips: false,
            };
            validate_ip_address(&ip, &strict)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Hostname validation helpers
// ---------------------------------------------------------------------------

/// SSRF-012: Block localhost, .local, .internal, .localhost.
fn validate_hostname_not_blocked(hostname: &str) -> ApiResult<()> {
    let lower = hostname.to_ascii_lowercase();

    for blocked in BLOCKED_HOSTNAMES {
        if lower == *blocked {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[SSRF] Blocked hostname: {}", hostname);
            return Err(ApiError::Forbidden(Some(
                "SSRF Protection: hostname is blocked".to_string(),
            )));
        }
    }

    for suffix in BLOCKED_HOSTNAME_SUFFIXES {
        // Match ".local" as a suffix or "local" as the full hostname.
        let bare_label = suffix.get(1..).unwrap_or(suffix); // strip leading dot
        if lower == bare_label || lower.ends_with(suffix) {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[SSRF] Blocked hostname suffix: {}", hostname);
            return Err(ApiError::Forbidden(Some(
                "SSRF Protection: hostname suffix is blocked".to_string(),
            )));
        }
    }

    Ok(())
}

/// SSRF-024: Block metadata hostnames.
fn validate_hostname_not_metadata(hostname: &str) -> ApiResult<()> {
    let lower = hostname.to_ascii_lowercase();

    for meta in METADATA_HOSTNAMES {
        if lower == *meta || lower.ends_with(&format!(".{}", meta)) {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[SSRF] Metadata hostname blocked: {}", hostname);
            return Err(ApiError::Forbidden(Some(
                "SSRF Protection: cloud metadata hostname is blocked".to_string(),
            )));
        }
    }

    Ok(())
}

/// SSRF-003: Validate hostname against allowlist with correct wildcard matching.
///
/// Wildcard entries like `*.example.com` match `sub.example.com` but NOT
/// `notexample.com`. An exact-match fallback also matches `example.com`.
fn validate_hostname_allowlist(hostname: &str, config: &SsrfConfig) -> ApiResult<()> {
    // Exact match
    if config.allowed_hosts.contains(&hostname.to_string()) {
        return Ok(());
    }

    // Wildcard subdomain match
    for allowed in &config.allowed_hosts {
        if let Some(domain) = allowed.strip_prefix("*.") {
            // SSRF-003: Match exact root domain or dot-prefixed suffix.
            let dot_domain = format!(".{}", domain);
            if hostname == domain || hostname.ends_with(&dot_domain) {
                return Ok(());
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    worker::console_log!(
        "[SSRF] Hostname not in allowlist: {} (allowed: {:?})",
        hostname,
        config.allowed_hosts
    );
    Err(ApiError::Forbidden(Some(format!(
        "Hostname '{}' is not in the SSRF allowlist",
        hostname
    ))))
}

// ---------------------------------------------------------------------------
// IP address validation
// ---------------------------------------------------------------------------

/// Validate an IP address against all SSRF restricted ranges.
pub fn validate_ip_address(ip: &IpAddr, config: &SsrfConfig) -> ApiResult<()> {
    match ip {
        IpAddr::V4(ipv4) => validate_ipv4_address(ipv4, config),
        IpAddr::V6(ipv6) => validate_ipv6_address(ipv6, config),
    }
}

/// Validate an IPv4 address.
fn validate_ipv4_address(ip: &Ipv4Addr, config: &SsrfConfig) -> ApiResult<()> {
    let ip_u32 = u32::from_be_bytes(ip.octets());

    // Loopback (127.0.0.0/8)
    if is_ipv4_loopback(ip_u32) {
        if config.allow_loopback {
            return Ok(());
        }
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] Loopback address blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: loopback addresses are not allowed".to_string(),
        )));
    }

    // Cloud metadata endpoint (169.254.169.254)
    if ip_u32 == CLOUD_METADATA_IP {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] Cloud metadata endpoint blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: cloud metadata endpoint is blocked".to_string(),
        )));
    }

    // Link-local (169.254.0.0/16)
    if is_ipv4_link_local(ip_u32) {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] Link-local address blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: link-local addresses are not allowed".to_string(),
        )));
    }

    // Private ranges (RFC 1918)
    if is_ipv4_private(ip_u32) {
        if config.allow_private_ips {
            return Ok(());
        }
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] Private IP range blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: private IP addresses are not allowed".to_string(),
        )));
    }

    // SSRF-006: CGNAT (100.64.0.0/10)
    if is_ipv4_cgnat(ip_u32) {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] CGNAT address blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: CGNAT addresses are not allowed".to_string(),
        )));
    }

    // SSRF-007: "This" network (0.0.0.0/8)
    if is_ipv4_this_network(ip_u32) {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] 'This' network address blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: 0.0.0.0/8 addresses are not allowed".to_string(),
        )));
    }

    // SSRF-007: Multicast (224.0.0.0/4)
    if is_ipv4_multicast(ip_u32) {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] Multicast address blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: multicast addresses are not allowed".to_string(),
        )));
    }

    // SSRF-007: Reserved (240.0.0.0/4) and broadcast (255.255.255.255)
    if is_ipv4_reserved(ip_u32) {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] Reserved address blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: reserved addresses are not allowed".to_string(),
        )));
    }

    // SSRF-022: RFC 5737 documentation ranges
    if is_ipv4_documentation(ip_u32) {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] Documentation address blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: documentation addresses are not allowed".to_string(),
        )));
    }

    // SSRF-027: Benchmarking range (198.18.0.0/15)
    if is_ipv4_benchmarking(ip_u32) {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] Benchmarking address blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: benchmarking addresses are not allowed".to_string(),
        )));
    }

    Ok(())
}

/// Validate an IPv6 address, including IPv4-mapped re-validation.
fn validate_ipv6_address(ip: &Ipv6Addr, config: &SsrfConfig) -> ApiResult<()> {
    // SSRF-008: Unspecified (::)
    if ip.is_unspecified() {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] IPv6 unspecified address blocked");
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: IPv6 unspecified address is not allowed".to_string(),
        )));
    }

    // Loopback (::1)
    if ip.is_loopback() {
        if config.allow_loopback {
            return Ok(());
        }
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] IPv6 loopback blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: IPv6 loopback is not allowed".to_string(),
        )));
    }

    // SSRF-008: Multicast (ff00::/8)
    if ip.is_multicast() {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] IPv6 multicast blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: IPv6 multicast addresses are not allowed".to_string(),
        )));
    }

    let segments = ip.segments();

    // Link-local (fe80::/10)
    if is_ipv6_link_local(ip) {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] IPv6 link-local blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: IPv6 link-local addresses are not allowed".to_string(),
        )));
    }

    // Unique Local Address (fc00::/7, IPv6 equivalent of private IPs)
    if is_ipv6_unique_local(ip) {
        if config.allow_private_ips {
            return Ok(());
        }
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] IPv6 unique local address blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: IPv6 unique local addresses are not allowed".to_string(),
        )));
    }

    // SSRF-008: Documentation (2001:db8::/32)
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] IPv6 documentation address blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: IPv6 documentation addresses are not allowed".to_string(),
        )));
    }

    // Site-local (fec0::/10, deprecated but still dangerous)
    if (segments[0] & 0xffc0) == 0xfec0 {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] IPv6 site-local address blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: IPv6 site-local addresses are not allowed".to_string(),
        )));
    }

    // AWS IMDSv2 (fd00:ec2::254)
    if segments[0] == 0xfd00
        && segments[1] == 0x0ec2
        && segments[2..7] == [0, 0, 0, 0, 0]
        && segments[7] == 0x0254
    {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[SSRF] AWS IMDSv2 IPv6 blocked: {}", ip);
        return Err(ApiError::Forbidden(Some(
            "SSRF Protection: cloud metadata endpoint is blocked".to_string(),
        )));
    }

    // SSRF-002: IPv4-mapped IPv6 (::ffff:0:0/96). Extract embedded IPv4
    // and re-validate it against all IPv4 rules.
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "[SSRF] IPv4-mapped IPv6 detected, re-validating embedded IPv4: {}",
            ipv4
        );
        return validate_ipv4_address(&ipv4, config);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// IPv4 range helpers
// ---------------------------------------------------------------------------

fn is_ipv4_loopback(ip: u32) -> bool {
    (LOOPBACK_IPV4_START..=LOOPBACK_IPV4_END).contains(&ip)
}

fn is_ipv4_link_local(ip: u32) -> bool {
    (LINK_LOCAL_IPV4_START..=LINK_LOCAL_IPV4_END).contains(&ip)
}

fn is_ipv4_private(ip: u32) -> bool {
    PRIVATE_IPV4_RANGES
        .iter()
        .any(|(start, end)| ip >= *start && ip <= *end)
}

fn is_ipv4_cgnat(ip: u32) -> bool {
    (CGNAT_IPV4_START..=CGNAT_IPV4_END).contains(&ip)
}

fn is_ipv4_this_network(ip: u32) -> bool {
    (THIS_NET_IPV4_START..=THIS_NET_IPV4_END).contains(&ip)
}

fn is_ipv4_multicast(ip: u32) -> bool {
    let first_octet = (ip >> 24) & 0xFF;
    (224..=239).contains(&first_octet)
}

fn is_ipv4_reserved(ip: u32) -> bool {
    let first_octet = (ip >> 24) & 0xFF;
    first_octet >= 240
}

fn is_ipv4_documentation(ip: u32) -> bool {
    DOC_IPV4_RANGES
        .iter()
        .any(|(start, end)| ip >= *start && ip <= *end)
}

fn is_ipv4_benchmarking(ip: u32) -> bool {
    (BENCH_IPV4_START..=BENCH_IPV4_END).contains(&ip)
}

// ---------------------------------------------------------------------------
// IPv6 range helpers
// ---------------------------------------------------------------------------

fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_unique_local(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

// ---------------------------------------------------------------------------
// Client-facing validation helpers
// ---------------------------------------------------------------------------

/// Validate an `issuer_kid` value for safe use in URL path construction.
///
/// SSRF-071: Blocks path traversal sequences, URL-special characters (`?`, `#`, `%`),
/// backslashes, and control characters.
pub fn validate_path_component(value: &str, field_name: &str) -> ApiResult<()> {
    if value.contains("..")
        || value.contains('/')
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value.contains('%')
    {
        return Err(ApiError::BadRequest(Some(format!(
            "{} contains invalid characters",
            field_name
        ))));
    }

    // Block control characters
    if value.chars().any(|c| c.is_control()) {
        return Err(ApiError::BadRequest(Some(format!(
            "{} contains control characters",
            field_name
        ))));
    }

    Ok(())
}

/// SSRF-011/074: Maximum response body size (1 MiB).
pub const MAX_RESPONSE_BODY_BYTES: usize = 1_048_576;

/// SSRF-020: Expected Content-Type for JSON API responses.
pub const EXPECTED_CONTENT_TYPE: &str = "application/json";

/// Check a Content-Type header value starts with `application/json`.
pub fn validate_content_type(content_type: Option<String>) -> ApiResult<()> {
    match content_type {
        Some(ct) if ct.starts_with(EXPECTED_CONTENT_TYPE) => Ok(()),
        Some(ct) => {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[SSRF] Unexpected Content-Type in response: {}", ct);
            Err(ApiError::BadRequest(Some(format!(
                "Unexpected Content-Type: {}",
                ct
            ))))
        }
        None => {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[SSRF] Missing Content-Type in response");
            Err(ApiError::BadRequest(Some(
                "Response missing Content-Type header".to_string(),
            )))
        }
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::string_slice
)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // IPv4 range helpers
    // ---------------------------------------------------------------------

    #[test]
    fn test_ipv4_loopback_detection() {
        assert!(is_ipv4_loopback(0x7F000001)); // 127.0.0.1
        assert!(is_ipv4_loopback(0x7F000000)); // 127.0.0.0
        assert!(is_ipv4_loopback(0x7FFFFFFF)); // 127.255.255.255
        assert!(!is_ipv4_loopback(0x7E000001)); // 126.0.0.1
        assert!(!is_ipv4_loopback(0x80000001)); // 128.0.0.1
    }

    #[test]
    fn test_ipv4_private_detection() {
        // 10.0.0.0/8
        assert!(is_ipv4_private(0x0A000000));
        assert!(is_ipv4_private(0x0AFFFFFF));
        // 172.16.0.0/12
        assert!(is_ipv4_private(0xAC100000));
        assert!(is_ipv4_private(0xAC1FFFFF));
        // 192.168.0.0/16
        assert!(is_ipv4_private(0xC0A80000));
        assert!(is_ipv4_private(0xC0A8FFFF));
        // Public
        assert!(!is_ipv4_private(0x08080808)); // 8.8.8.8
    }

    #[test]
    fn test_ipv4_link_local_detection() {
        assert!(is_ipv4_link_local(0xA9FE0000));
        assert!(is_ipv4_link_local(0xA9FEFFFF));
        assert!(!is_ipv4_link_local(0xA9FD0000));
    }

    #[test]
    fn test_ipv4_cgnat_detection() {
        // 100.64.0.0
        assert!(is_ipv4_cgnat(0x64400000));
        // 100.64.0.1
        assert!(is_ipv4_cgnat(0x64400001));
        // 100.127.255.255
        assert!(is_ipv4_cgnat(0x647FFFFF));
        // 100.63.255.255 (just below)
        assert!(!is_ipv4_cgnat(0x643FFFFF));
        // 100.128.0.0 (just above)
        assert!(!is_ipv4_cgnat(0x64800000));
    }

    #[test]
    fn test_ipv4_this_network() {
        assert!(is_ipv4_this_network(0x00000000)); // 0.0.0.0
        assert!(is_ipv4_this_network(0x00FFFFFF)); // 0.255.255.255
        assert!(!is_ipv4_this_network(0x01000000)); // 1.0.0.0
    }

    #[test]
    fn test_ipv4_multicast() {
        assert!(is_ipv4_multicast(0xE0000001)); // 224.0.0.1
        assert!(is_ipv4_multicast(0xEFFFFFFF)); // 239.255.255.255
        assert!(!is_ipv4_multicast(0xDFFFFFFF)); // 223.255.255.255
    }

    #[test]
    fn test_ipv4_reserved() {
        assert!(is_ipv4_reserved(0xF0000000)); // 240.0.0.0
        assert!(is_ipv4_reserved(0xFFFFFFFF)); // 255.255.255.255 (broadcast)
        assert!(!is_ipv4_reserved(0xEFFFFFFF)); // 239.255.255.255
    }

    #[test]
    fn test_ipv4_documentation_ranges() {
        // TEST-NET-1: 192.0.2.0/24
        assert!(is_ipv4_documentation(0xC0000200));
        assert!(is_ipv4_documentation(0xC00002FF));
        assert!(!is_ipv4_documentation(0xC0000300));
        // TEST-NET-2: 198.51.100.0/24
        assert!(is_ipv4_documentation(0xC6336400));
        assert!(is_ipv4_documentation(0xC63364FF));
        // TEST-NET-3: 203.0.113.0/24
        assert!(is_ipv4_documentation(0xCB007100));
        assert!(is_ipv4_documentation(0xCB0071FF));
    }

    #[test]
    fn test_ipv4_benchmarking() {
        // 198.18.0.0
        assert!(is_ipv4_benchmarking(0xC6120000));
        // 198.19.255.255
        assert!(is_ipv4_benchmarking(0xC613FFFF));
        // 198.17.255.255 (below range)
        assert!(!is_ipv4_benchmarking(0xC611FFFF));
        // 198.20.0.0 (above range)
        assert!(!is_ipv4_benchmarking(0xC6140000));
    }

    // ---------------------------------------------------------------------
    // IPv6 helpers
    // ---------------------------------------------------------------------

    #[test]
    fn test_ipv6_link_local() -> Result<(), Box<dyn std::error::Error>> {
        let ip = "fe80::1".parse::<Ipv6Addr>()?;
        assert!(is_ipv6_link_local(&ip));
        let ip2 = "fe70::1".parse::<Ipv6Addr>()?;
        assert!(!is_ipv6_link_local(&ip2));
        Ok(())
    }

    #[test]
    fn test_ipv6_unique_local() -> Result<(), Box<dyn std::error::Error>> {
        let ip = "fc00::1".parse::<Ipv6Addr>()?;
        assert!(is_ipv6_unique_local(&ip));
        let ip2 = "fd00::1".parse::<Ipv6Addr>()?;
        assert!(is_ipv6_unique_local(&ip2));
        let ip3 = "fe00::1".parse::<Ipv6Addr>()?;
        assert!(!is_ipv6_unique_local(&ip3));
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Hostname blocklist
    // ---------------------------------------------------------------------

    #[test]
    fn test_blocked_hostnames() {
        assert!(validate_hostname_not_blocked("localhost").is_err());
        assert!(validate_hostname_not_blocked("printer.local").is_err());
        assert!(validate_hostname_not_blocked("local").is_err());
        assert!(validate_hostname_not_blocked("host.internal").is_err());
        assert!(validate_hostname_not_blocked("internal").is_err());
        assert!(validate_hostname_not_blocked("app.localhost").is_err());
        assert!(validate_hostname_not_blocked("example.com").is_ok());
    }

    #[test]
    fn test_metadata_hostnames() {
        assert!(validate_hostname_not_metadata("metadata.google.internal").is_err());
        assert!(validate_hostname_not_metadata("metadata.goog").is_err());
        assert!(validate_hostname_not_metadata("metadata").is_err());
        assert!(validate_hostname_not_metadata("sub.metadata.goog").is_err());
        assert!(validate_hostname_not_metadata("example.com").is_ok());
    }

    // ---------------------------------------------------------------------
    // Wildcard suffix matching (SSRF-003)
    // ---------------------------------------------------------------------

    #[test]
    fn test_wildcard_suffix_exact_match() {
        // *.example.com should NOT match "notexample.com"
        let config = SsrfConfig::new(vec!["*.example.com".to_string()]);
        assert!(validate_hostname_allowlist("notexample.com", &config).is_err());
        // But should match "sub.example.com" and "example.com"
        assert!(validate_hostname_allowlist("sub.example.com", &config).is_ok());
        assert!(validate_hostname_allowlist("example.com", &config).is_ok());
    }

    // ---------------------------------------------------------------------
    // Path component validation (SSRF-071)
    // ---------------------------------------------------------------------

    #[test]
    fn test_validate_path_component() {
        assert!(validate_path_component("issuer-123", "kid").is_ok());
        assert!(validate_path_component("../etc/passwd", "kid").is_err());
        assert!(validate_path_component("foo/bar", "kid").is_err());
        assert!(validate_path_component("foo?bar", "kid").is_err());
        assert!(validate_path_component("foo#bar", "kid").is_err());
        assert!(validate_path_component("foo%2F", "kid").is_err());
        assert!(validate_path_component("foo\\bar", "kid").is_err());
        assert!(validate_path_component("foo\x00bar", "kid").is_err());
    }

    // ---------------------------------------------------------------------
    // Content-Type validation (SSRF-020)
    // ---------------------------------------------------------------------

    #[test]
    fn test_validate_content_type() {
        assert!(validate_content_type(Some("application/json".to_string())).is_ok());
        assert!(validate_content_type(Some("application/json; charset=utf-8".to_string())).is_ok());
        assert!(validate_content_type(Some("text/html".to_string())).is_err());
        assert!(validate_content_type(None).is_err());
    }

    // ---------------------------------------------------------------------
    // Base URL validation (SSRF-070)
    // ---------------------------------------------------------------------

    #[test]
    fn test_validate_base_url() {
        assert!(validate_base_url("https://api.example.com").is_ok());
        assert!(validate_base_url("http://api.example.com").is_err());
        assert!(validate_base_url("https://api.example.com:8080").is_err());
        assert!(validate_base_url("https://localhost").is_err());
        assert!(validate_base_url("https://api.example.com:443").is_ok());
    }

    // ---------------------------------------------------------------------
    // SsrfConfig
    // ---------------------------------------------------------------------

    #[test]
    fn test_ssrf_config_default() {
        let config = SsrfConfig::default();
        assert_eq!(config.allowed_hosts.len(), 1);
        assert_eq!(config.allowed_hosts[0], "cdn.provii.app");
        assert!(!config.allow_loopback);
        assert!(!config.allow_private_ips);
    }

    #[test]
    fn test_ssrf_config_from_env() {
        let env_var = Some("cdn.provii.app,api.example.com".to_string());
        let config = SsrfConfig::from_env(env_var);
        assert_eq!(config.allowed_hosts.len(), 2);
    }

    #[test]
    fn test_ssrf_config_from_env_empty() {
        let config = SsrfConfig::from_env(None);
        assert_eq!(config.allowed_hosts.len(), 1);
    }

    #[test]
    fn test_ssrf_config_from_env_with_whitespace() {
        let env_var = Some("  cdn.provii.app  ,  api.example.com  ".to_string());
        let config = SsrfConfig::from_env(env_var);
        assert_eq!(config.allowed_hosts.len(), 2);
        assert!(config.allowed_hosts.contains(&"cdn.provii.app".to_string()));
        assert!(config
            .allowed_hosts
            .contains(&"api.example.com".to_string()));
    }

    // ---------------------------------------------------------------------
    // Property-based tests
    // ---------------------------------------------------------------------

    // ---------------------------------------------------------------------
    // Additional path component validation (SSRF-071)
    // ---------------------------------------------------------------------

    #[test]
    fn test_validate_path_component_empty() {
        assert!(validate_path_component("", "kid").is_ok());
    }

    #[test]
    fn test_validate_path_component_alphanumeric() {
        assert!(validate_path_component("abc123XYZ", "kid").is_ok());
    }

    #[test]
    fn test_validate_path_component_with_dash_underscore() {
        assert!(validate_path_component("issuer-key_123", "kid").is_ok());
    }

    #[test]
    fn test_validate_path_component_double_dot_no_slash() {
        assert!(validate_path_component("foo..bar", "kid").is_err());
    }

    #[test]
    fn test_validate_path_component_percent_encoding() {
        assert!(validate_path_component("foo%2Fbar", "kid").is_err());
    }

    #[test]
    fn test_validate_path_component_newline() {
        assert!(validate_path_component("foo\nbar", "kid").is_err());
    }

    #[test]
    fn test_validate_path_component_carriage_return() {
        assert!(validate_path_component("foo\rbar", "kid").is_err());
    }

    // ---------------------------------------------------------------------
    // Additional content type validation
    // ---------------------------------------------------------------------

    #[test]
    fn test_validate_content_type_xml() {
        assert!(validate_content_type(Some("application/xml".to_string())).is_err());
    }

    #[test]
    fn test_validate_content_type_empty_string() {
        assert!(validate_content_type(Some("".to_string())).is_err());
    }

    #[test]
    fn test_validate_content_type_json_with_params() {
        assert!(validate_content_type(Some(
            "application/json; charset=utf-8; boundary=something".to_string()
        ))
        .is_ok());
    }

    // ---------------------------------------------------------------------
    // Additional hostname validation
    // ---------------------------------------------------------------------

    #[test]
    fn test_blocked_hostnames_case_insensitive() {
        assert!(validate_hostname_not_blocked("LOCALHOST").is_err());
        assert!(validate_hostname_not_blocked("Localhost").is_err());
    }

    #[test]
    fn test_blocked_hostname_suffix_deep_nesting() {
        assert!(validate_hostname_not_blocked("deep.nested.host.local").is_err());
    }

    #[test]
    fn test_metadata_hostname_case_insensitive() {
        assert!(validate_hostname_not_metadata("METADATA.GOOGLE.INTERNAL").is_err());
        assert!(validate_hostname_not_metadata("Metadata.Goog").is_err());
    }

    // ---------------------------------------------------------------------
    // Additional hostname allowlist
    // ---------------------------------------------------------------------

    #[test]
    fn test_allowlist_empty_rejects_all() {
        let config = SsrfConfig::new(vec![]);
        assert!(validate_hostname_allowlist("example.com", &config).is_err());
    }

    #[test]
    fn test_allowlist_exact_match_case_sensitive() {
        let config = SsrfConfig::new(vec!["CDN.Example.Com".to_string()]);
        // Exact match is case-sensitive in the current impl
        assert!(validate_hostname_allowlist("CDN.Example.Com", &config).is_ok());
        assert!(validate_hostname_allowlist("cdn.example.com", &config).is_err());
    }

    #[test]
    fn test_allowlist_wildcard_root_domain_matches() {
        let config = SsrfConfig::new(vec!["*.example.com".to_string()]);
        // SSRF-003: Root domain also matches wildcard
        assert!(validate_hostname_allowlist("example.com", &config).is_ok());
    }

    #[test]
    fn test_allowlist_wildcard_suffix_attack_rejects() {
        let config = SsrfConfig::new(vec!["*.example.com".to_string()]);
        assert!(validate_hostname_allowlist("evilexample.com", &config).is_err());
    }

    #[test]
    fn test_allowlist_multiple_wildcards() {
        let config = SsrfConfig::new(vec!["*.a.com".to_string(), "*.b.com".to_string()]);
        assert!(validate_hostname_allowlist("sub.a.com", &config).is_ok());
        assert!(validate_hostname_allowlist("sub.b.com", &config).is_ok());
        assert!(validate_hostname_allowlist("sub.c.com", &config).is_err());
    }

    // ---------------------------------------------------------------------
    // Additional IPv4 range tests
    // ---------------------------------------------------------------------

    #[test]
    fn test_ipv4_private_172_boundary() {
        // 172.15.255.255 is NOT private (just below 172.16.0.0/12)
        assert!(!is_ipv4_private(0xAC0FFFFF));
        // 172.32.0.0 is NOT private (just above 172.31.255.255)
        assert!(!is_ipv4_private(0xAC200000));
    }

    #[test]
    fn test_ipv4_loopback_boundary() {
        // 126.255.255.255 is NOT loopback
        assert!(!is_ipv4_loopback(0x7EFFFFFF));
        // 128.0.0.0 is NOT loopback
        assert!(!is_ipv4_loopback(0x80000000));
    }

    // ---------------------------------------------------------------------
    // SsrfConfig additional tests
    // ---------------------------------------------------------------------

    #[test]
    fn test_ssrf_config_new() {
        let config = SsrfConfig::new(vec!["host.com".to_string()]);
        assert_eq!(config.allowed_hosts, vec!["host.com".to_string()]);
        assert!(!config.allow_loopback);
        assert!(!config.allow_private_ips);
    }

    #[test]
    fn test_ssrf_config_from_env_empty_entries_filtered() {
        let env_var = Some(",,,host.com,,,".to_string());
        let config = SsrfConfig::from_env(env_var);
        assert_eq!(config.allowed_hosts, vec!["host.com".to_string()]);
    }

    #[test]
    fn test_ssrf_config_debug() {
        let config = SsrfConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("SsrfConfig"));
        assert!(debug.contains("cdn.provii.app"));
    }

    #[test]
    fn test_ssrf_config_clone() {
        let config = SsrfConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.allowed_hosts, config.allowed_hosts);
        assert_eq!(cloned.allow_loopback, config.allow_loopback);
        assert_eq!(cloned.allow_private_ips, config.allow_private_ips);
    }

    // ---------------------------------------------------------------------
    // Constants validation
    // ---------------------------------------------------------------------

    #[test]
    fn test_max_response_body_bytes() {
        assert_eq!(MAX_RESPONSE_BODY_BYTES, 1_048_576);
    }

    #[test]
    fn test_expected_content_type() {
        assert_eq!(EXPECTED_CONTENT_TYPE, "application/json");
    }

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    // ---------------------------------------------------------------------
    // validate_ip_address() (public dispatch)
    // ---------------------------------------------------------------------

    #[test]
    fn test_validate_ip_address_public_ipv4_allowed() -> Result<(), Box<dyn std::error::Error>> {
        let ip: IpAddr = "8.8.8.8".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ip_address(&ip, &config).is_ok());
        Ok(())
    }

    #[test]
    fn test_validate_ip_address_loopback_v4_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: IpAddr = "127.0.0.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ip_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_validate_ip_address_loopback_v6_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: IpAddr = "::1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ip_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_validate_ip_address_dispatches_v6() -> Result<(), Box<dyn std::error::Error>> {
        let ip: IpAddr = "2001:db8::1".parse()?;
        let config = SsrfConfig::new(vec![]);
        // IPv6 documentation address should be blocked
        assert!(validate_ip_address(&ip, &config).is_err());
        Ok(())
    }

    // ---------------------------------------------------------------------
    // validate_ipv4_address() with config flags
    // ---------------------------------------------------------------------

    #[test]
    fn test_ipv4_loopback_allowed_with_config() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "127.0.0.1".parse()?;
        let mut config = SsrfConfig::new(vec![]);
        config.allow_loopback = true;
        assert!(validate_ipv4_address(&ip, &config).is_ok());
        Ok(())
    }

    #[test]
    fn test_ipv4_loopback_blocked_without_config() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "127.0.0.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_private_allowed_with_config() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "10.0.0.1".parse()?;
        let mut config = SsrfConfig::new(vec![]);
        config.allow_private_ips = true;
        assert!(validate_ipv4_address(&ip, &config).is_ok());
        Ok(())
    }

    #[test]
    fn test_ipv4_private_blocked_without_config() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "10.0.0.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_cloud_metadata_always_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "169.254.169.254".parse()?;
        let mut config = SsrfConfig::new(vec![]);
        config.allow_loopback = true;
        config.allow_private_ips = true;
        // Metadata endpoint is blocked even with permissive config
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_link_local_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "169.254.1.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_cgnat_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "100.64.0.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_this_network_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "0.0.0.0".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_multicast_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "224.0.0.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_reserved_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "240.0.0.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_broadcast_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "255.255.255.255".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_documentation_test_net_1_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "192.0.2.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_documentation_test_net_2_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "198.51.100.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_documentation_test_net_3_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "203.0.113.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_benchmarking_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "198.18.0.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_public_address_allowed() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "8.8.8.8".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_ok());
        Ok(())
    }

    #[test]
    fn test_ipv4_private_172_16_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "172.16.0.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_private_192_168_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "192.168.1.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv4_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv4_private_172_16_allowed_with_config() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "172.16.0.1".parse()?;
        let mut config = SsrfConfig::new(vec![]);
        config.allow_private_ips = true;
        assert!(validate_ipv4_address(&ip, &config).is_ok());
        Ok(())
    }

    #[test]
    fn test_ipv4_private_192_168_allowed_with_config() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv4Addr = "192.168.1.1".parse()?;
        let mut config = SsrfConfig::new(vec![]);
        config.allow_private_ips = true;
        assert!(validate_ipv4_address(&ip, &config).is_ok());
        Ok(())
    }

    // ---------------------------------------------------------------------
    // validate_ipv6_address() paths
    // ---------------------------------------------------------------------

    #[test]
    fn test_ipv6_unspecified_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "::".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_loopback_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "::1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_loopback_allowed_with_config() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "::1".parse()?;
        let mut config = SsrfConfig::new(vec![]);
        config.allow_loopback = true;
        assert!(validate_ipv6_address(&ip, &config).is_ok());
        Ok(())
    }

    #[test]
    fn test_ipv6_multicast_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "ff02::1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_link_local_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "fe80::1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_unique_local_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "fd00::1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_unique_local_allowed_with_config() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "fd00::1".parse()?;
        let mut config = SsrfConfig::new(vec![]);
        config.allow_private_ips = true;
        assert!(validate_ipv6_address(&ip, &config).is_ok());
        Ok(())
    }

    #[test]
    fn test_ipv6_fc00_unique_local_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "fc00::1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_fc00_unique_local_allowed_with_config() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "fc00::1".parse()?;
        let mut config = SsrfConfig::new(vec![]);
        config.allow_private_ips = true;
        assert!(validate_ipv6_address(&ip, &config).is_ok());
        Ok(())
    }

    #[test]
    fn test_ipv6_documentation_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "2001:db8::1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_documentation_2001_db8_ffff_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "2001:db8:ffff::1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_site_local_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "fec0::1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_site_local_feff_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "feff::1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_aws_imdsv2_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "fd00:ec2::254".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_aws_imdsv2_not_other_fd00_ec2() -> Result<(), Box<dyn std::error::Error>> {
        // fd00:ec2::255 is NOT the IMDSv2 endpoint; it falls through to
        // unique-local check instead.
        let ip: Ipv6Addr = "fd00:ec2::255".parse()?;
        let config = SsrfConfig::new(vec![]);
        // Still blocked, but by unique-local rule, not IMDSv2 rule
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_mapped_ipv4_loopback_blocked() -> Result<(), Box<dyn std::error::Error>> {
        // ::ffff:127.0.0.1 is IPv4-mapped IPv6 for loopback
        let ip: Ipv6Addr = "::ffff:127.0.0.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_mapped_ipv4_private_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "::ffff:10.0.0.1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_mapped_ipv4_public_allowed() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "::ffff:8.8.8.8".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_ok());
        Ok(())
    }

    #[test]
    fn test_ipv6_mapped_ipv4_metadata_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "::ffff:169.254.169.254".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    #[test]
    fn test_ipv6_mapped_ipv4_loopback_allowed_with_config() -> Result<(), Box<dyn std::error::Error>>
    {
        let ip: Ipv6Addr = "::ffff:127.0.0.1".parse()?;
        let mut config = SsrfConfig::new(vec![]);
        config.allow_loopback = true;
        assert!(validate_ipv6_address(&ip, &config).is_ok());
        Ok(())
    }

    #[test]
    fn test_ipv6_mapped_ipv4_private_allowed_with_config() -> Result<(), Box<dyn std::error::Error>>
    {
        let ip: Ipv6Addr = "::ffff:192.168.1.1".parse()?;
        let mut config = SsrfConfig::new(vec![]);
        config.allow_private_ips = true;
        assert!(validate_ipv6_address(&ip, &config).is_ok());
        Ok(())
    }

    #[test]
    fn test_ipv6_global_unicast_allowed() -> Result<(), Box<dyn std::error::Error>> {
        // A normal global unicast IPv6 address should pass
        let ip: Ipv6Addr = "2606:4700:4700::1111".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_ok());
        Ok(())
    }

    #[test]
    fn test_ipv6_multicast_ff0e_blocked() -> Result<(), Box<dyn std::error::Error>> {
        let ip: Ipv6Addr = "ff0e::1".parse()?;
        let config = SsrfConfig::new(vec![]);
        assert!(validate_ipv6_address(&ip, &config).is_err());
        Ok(())
    }

    // ---------------------------------------------------------------------
    // validate_base_url() additional coverage
    // ---------------------------------------------------------------------

    #[test]
    fn test_validate_base_url_invalid_url() {
        assert!(validate_base_url("not a url").is_err());
    }

    #[test]
    fn test_validate_base_url_with_private_ip() {
        assert!(validate_base_url("https://10.0.0.1").is_err());
    }

    #[test]
    fn test_validate_base_url_with_loopback_ip() {
        assert!(validate_base_url("https://127.0.0.1").is_err());
    }

    #[test]
    fn test_validate_base_url_with_metadata_hostname() {
        assert!(validate_base_url("https://metadata.goog").is_err());
    }

    #[test]
    fn test_validate_base_url_with_metadata_google_internal() {
        assert!(validate_base_url("https://metadata.google.internal").is_err());
    }

    #[test]
    fn test_validate_base_url_with_ipv6_loopback() {
        assert!(validate_base_url("https://[::1]").is_err());
    }

    #[test]
    fn test_validate_base_url_ftp_scheme() {
        assert!(validate_base_url("ftp://example.com").is_err());
    }

    #[test]
    fn test_validate_base_url_port_8080_blocked() {
        assert!(validate_base_url("https://example.com:8080").is_err());
    }

    #[test]
    fn test_validate_base_url_port_443_ok() {
        assert!(validate_base_url("https://example.com:443").is_ok());
    }

    #[test]
    fn test_validate_base_url_no_port_ok() {
        assert!(validate_base_url("https://api.provii.app").is_ok());
    }

    #[test]
    fn test_validate_base_url_with_path() {
        // URL with path should still pass basic validation
        assert!(validate_base_url("https://api.example.com/v1").is_ok());
    }

    #[test]
    fn test_validate_base_url_localhost_localdomain() {
        assert!(validate_base_url("https://localhost.localdomain").is_err());
    }

    #[test]
    fn test_validate_base_url_dot_local() {
        assert!(validate_base_url("https://printer.local").is_err());
    }

    // ---------------------------------------------------------------------
    // validate_hostname_not_blocked() additional
    // ---------------------------------------------------------------------

    #[test]
    fn test_blocked_hostname_localhost_localdomain() {
        assert!(validate_hostname_not_blocked("localhost.localdomain").is_err());
    }

    #[test]
    fn test_blocked_hostname_localhost_suffix() {
        // "app.localhost" ends with ".localhost"
        assert!(validate_hostname_not_blocked("foo.bar.localhost").is_err());
    }

    #[test]
    fn test_hostname_not_blocked_normal_domain() {
        assert!(validate_hostname_not_blocked("cdn.provii.app").is_ok());
    }

    #[test]
    fn test_hostname_not_blocked_internal_as_bare_label() {
        assert!(validate_hostname_not_blocked("internal").is_err());
    }

    // ---------------------------------------------------------------------
    // validate_hostname_not_metadata() additional
    // ---------------------------------------------------------------------

    #[test]
    fn test_metadata_hostname_bare_metadata() {
        assert!(validate_hostname_not_metadata("metadata").is_err());
    }

    #[test]
    fn test_metadata_hostname_subdomain_of_metadata_goog() {
        assert!(validate_hostname_not_metadata("evil.metadata.goog").is_err());
    }

    #[test]
    fn test_metadata_hostname_not_matched_for_normal() {
        assert!(validate_hostname_not_metadata("cdn.provii.app").is_ok());
    }

    // ---------------------------------------------------------------------
    // validate_hostname_allowlist() additional
    // ---------------------------------------------------------------------

    #[test]
    fn test_allowlist_wildcard_deep_subdomain() {
        let config = SsrfConfig::new(vec!["*.example.com".to_string()]);
        assert!(validate_hostname_allowlist("a.b.c.d.example.com", &config).is_ok());
    }

    #[test]
    fn test_allowlist_mixed_exact_and_wildcard() {
        let config = SsrfConfig::new(vec!["exact.com".to_string(), "*.wildcard.com".to_string()]);
        assert!(validate_hostname_allowlist("exact.com", &config).is_ok());
        assert!(validate_hostname_allowlist("sub.wildcard.com", &config).is_ok());
        assert!(validate_hostname_allowlist("other.com", &config).is_err());
    }

    #[test]
    fn test_allowlist_wildcard_does_not_match_partial() {
        let config = SsrfConfig::new(vec!["*.example.com".to_string()]);
        assert!(validate_hostname_allowlist("myexample.com", &config).is_err());
    }

    // ---------------------------------------------------------------------
    // SsrfConfig additional
    // ---------------------------------------------------------------------

    #[test]
    fn test_ssrf_config_from_env_all_whitespace_entries() {
        let env_var = Some(" , , , ".to_string());
        let config = SsrfConfig::from_env(env_var);
        assert!(config.allowed_hosts.is_empty());
    }

    #[test]
    fn test_ssrf_config_from_env_single_host() {
        let env_var = Some("single.host.com".to_string());
        let config = SsrfConfig::from_env(env_var);
        assert_eq!(config.allowed_hosts.len(), 1);
        assert!(config
            .allowed_hosts
            .contains(&"single.host.com".to_string()));
    }

    // ---------------------------------------------------------------------
    // validate_path_component() additional
    // ---------------------------------------------------------------------

    #[test]
    fn test_validate_path_component_tab_control_char() {
        assert!(validate_path_component("foo\tbar", "kid").is_err());
    }

    #[test]
    fn test_validate_path_component_bell_control_char() {
        assert!(validate_path_component("foo\x07bar", "kid").is_err());
    }

    #[test]
    fn test_validate_path_component_unicode_allowed() {
        // Non-ASCII, non-control characters should be allowed
        assert!(validate_path_component("caf\u{00e9}", "kid").is_ok());
    }

    #[test]
    fn test_validate_path_component_dot_dot_at_start() {
        assert!(validate_path_component("..foo", "kid").is_err());
    }

    // ---------------------------------------------------------------------
    // validate_content_type() additional
    // ---------------------------------------------------------------------

    #[test]
    fn test_validate_content_type_case_sensitive() {
        // "Application/JSON" does not match "application/json"
        assert!(validate_content_type(Some("Application/JSON".to_string())).is_err());
    }

    #[test]
    fn test_validate_content_type_application_json_ld() {
        // "application/json-ld" does not start with "application/json"
        // Actually it does start with "application/json" since "application/json" is a prefix of "application/json-ld"
        assert!(validate_content_type(Some("application/json-ld".to_string())).is_ok());
    }

    #[test]
    fn test_validate_content_type_text_plain() {
        assert!(validate_content_type(Some("text/plain".to_string())).is_err());
    }

    #[test]
    fn test_validate_path_component_single_dot_allowed() {
        assert!(validate_path_component(".", "kid").is_ok());
    }

    #[test]
    fn test_validate_path_component_only_backslash() {
        assert!(validate_path_component("\\", "kid").is_err());
    }

    #[test]
    fn test_validate_path_component_only_percent() {
        assert!(validate_path_component("%", "kid").is_err());
    }

    #[test]
    fn test_validate_path_component_only_question_mark() {
        assert!(validate_path_component("?", "kid").is_err());
    }

    #[test]
    fn test_validate_path_component_error_includes_field_name() {
        let err = validate_path_component("../x", "issuer_kid").unwrap_err();
        // ApiError Display outputs the variant label ("bad-request"), not the
        // inner payload. Use Debug to inspect the full message including the
        // field name from the BadRequest(Some(...)) payload.
        let msg = format!("{:?}", err);
        assert!(msg.contains("issuer_kid"));
    }

    #[test]
    fn test_validate_content_type_leading_whitespace_rejected() {
        assert!(validate_content_type(Some(" application/json".to_string())).is_err());
    }

    #[test]
    fn test_validate_content_type_close_prefix_rejected() {
        assert!(validate_content_type(Some("application/jso".to_string())).is_err());
    }

    #[test]
    fn test_validate_content_type_whitespace_only_rejected() {
        assert!(validate_content_type(Some("   ".to_string())).is_err());
    }

    #[test]
    fn test_validate_path_component_hash_only() {
        assert!(validate_path_component("#", "kid").is_err());
    }

    #[test]
    fn test_validate_content_type_uppercase_json_rejected() {
        assert!(validate_content_type(Some("APPLICATION/JSON".to_string())).is_err());
    }

    // ---------------------------------------------------------------------
    // Property-based tests
    // ---------------------------------------------------------------------

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// All 127.x.x.x addresses are loopback.
        #[test]
        fn prop_loopback_range(b in 0u8..=255, c in 0u8..=255, d in 0u8..=255) {
            let ip = Ipv4Addr::new(127, b, c, d);
            let ip_u32 = u32::from_be_bytes(ip.octets());
            prop_assert!(is_ipv4_loopback(ip_u32));
        }

        /// All 10.x.x.x addresses are private.
        #[test]
        fn prop_private_10_range(b in 0u8..=255, c in 0u8..=255, d in 0u8..=255) {
            let ip = Ipv4Addr::new(10, b, c, d);
            let ip_u32 = u32::from_be_bytes(ip.octets());
            prop_assert!(is_ipv4_private(ip_u32));
        }

        /// All 192.168.x.x addresses are private.
        #[test]
        fn prop_private_192_168_range(c in 0u8..=255, d in 0u8..=255) {
            let ip = Ipv4Addr::new(192, 168, c, d);
            let ip_u32 = u32::from_be_bytes(ip.octets());
            prop_assert!(is_ipv4_private(ip_u32));
        }

        /// CGNAT range: 100.64-127.x.x.
        #[test]
        fn prop_cgnat_range(b in 64u8..=127, c in 0u8..=255, d in 0u8..=255) {
            let ip = Ipv4Addr::new(100, b, c, d);
            let ip_u32 = u32::from_be_bytes(ip.octets());
            prop_assert!(is_ipv4_cgnat(ip_u32));
        }

        /// Multicast range: 224-239.x.x.x.
        #[test]
        fn prop_multicast_range(a in 224u8..=239, b in 0u8..=255, c in 0u8..=255, d in 0u8..=255) {
            let ip = Ipv4Addr::new(a, b, c, d);
            let ip_u32 = u32::from_be_bytes(ip.octets());
            prop_assert!(is_ipv4_multicast(ip_u32));
        }

        /// All reserved (240-255.x.x.x) addresses are detected.
        #[test]
        fn prop_reserved_range(a in 240u8..=255, b in 0u8..=255, c in 0u8..=255, d in 0u8..=255) {
            let ip = Ipv4Addr::new(a, b, c, d);
            let ip_u32 = u32::from_be_bytes(ip.octets());
            prop_assert!(is_ipv4_reserved(ip_u32));
        }

        /// All 0.x.x.x addresses are "this network".
        #[test]
        fn prop_this_network_range(b in 0u8..=255, c in 0u8..=255, d in 0u8..=255) {
            let ip = Ipv4Addr::new(0, b, c, d);
            let ip_u32 = u32::from_be_bytes(ip.octets());
            prop_assert!(is_ipv4_this_network(ip_u32));
        }

        /// Link-local: 169.254.x.x
        #[test]
        fn prop_link_local_range(c in 0u8..=255, d in 0u8..=255) {
            let ip = Ipv4Addr::new(169, 254, c, d);
            let ip_u32 = u32::from_be_bytes(ip.octets());
            prop_assert!(is_ipv4_link_local(ip_u32));
        }

        /// 172.16-31.x.x addresses are private.
        #[test]
        fn prop_private_172_range(b in 16u8..=31, c in 0u8..=255, d in 0u8..=255) {
            let ip = Ipv4Addr::new(172, b, c, d);
            let ip_u32 = u32::from_be_bytes(ip.octets());
            prop_assert!(is_ipv4_private(ip_u32));
        }
    }
}
