// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Cookie generation and parsing utilities for session management.
//!
//! Provides secure cookie generation with appropriate security attributes for
//! storing HMAC-signed session tokens. Every cookie emitted by this module
//! carries HttpOnly (preventing JavaScript access), Secure (HTTPS-only
//! transmission), a SameSite policy, an explicit Max-Age, and a root Path.
//!
//! The default configuration uses the `__Host-` cookie prefix defined in
//! RFC 6265bis. That prefix forces four browser-enforced constraints: the
//! Secure flag must be set, the Path must be `/`, no Domain attribute may
//! be present, and the cookie is bound to the exact origin that set it.
//! Together these prevent subdomain cookie injection, cookie tossing, and
//! protocol downgrade attacks. A subdomain such as evil.provii.app
//! cannot overwrite cookies belonging to hosted.provii.app, and an
//! attacker on a related domain cannot shadow the legitimate session cookie.

use std::fmt;

// SECURITY: Cookie configuration for HMAC-signed session tokens. The __Host-
// prefix enforces Secure, Path=/, and no Domain attribute at the browser level.
// SameSite policy provides CSRF protection. HttpOnly prevents XSS exfiltration.

/// Cookie configuration for HMAC-signed session tokens.
///
/// When using the `__Host-` cookie prefix, browsers enforce four constraints:
/// `domain` must be `None`, `path` must be `"/"`, `secure` must be `true`,
/// and no Domain attribute appears in the Set-Cookie header. Violating any of
/// these causes the browser to silently reject the cookie.
#[derive(Debug, Clone)]
pub struct CookieConfig {
    /// Cookie name. Defaults to `"__Host-session"` for origin-locked security.
    pub name: String,

    /// Optional Domain attribute (e.g. `".provii.app"`). Must be `None`
    /// when using the `__Host-` prefix.
    pub domain: Option<String>,

    /// Path attribute. Must be `"/"` when using the `__Host-` prefix.
    pub path: String,

    /// Max-Age in seconds (default: 86400, i.e. 24 hours).
    pub max_age: u64,

    /// HttpOnly flag. Should always be `true` to prevent JavaScript access.
    pub http_only: bool,

    /// Secure flag. Must be `true` when using the `__Host-` prefix.
    pub secure: bool,

    /// SameSite policy for CSRF protection.
    pub same_site: SameSitePolicy,
}

/// SameSite cookie attribute values (CSRF protection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSitePolicy {
    /// Allow cookies on top-level navigations. Suitable when users arrive
    /// via external links but cross-origin subresource requests should
    /// still be blocked.
    Lax,

    /// Never send cookies in cross-site requests. Strongest CSRF protection
    /// but may affect usability when users follow inbound links.
    Strict,

    /// Always send cookies (requires the Secure flag). Only appropriate when
    /// cross-site access is genuinely required.
    None,
}

impl fmt::Display for SameSitePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SameSitePolicy::Lax => write!(f, "Lax"),
            SameSitePolicy::Strict => write!(f, "Strict"),
            SameSitePolicy::None => write!(f, "None"),
        }
    }
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            // SECURITY: __Host- prefix enforces origin-locked, HTTPS-only cookies
            name: "__Host-session".to_string(),
            // SECURITY: Domain must be None for __Host- prefix (same-origin policy)
            domain: None,
            // SECURITY: Path must be "/" for __Host- prefix
            path: "/".to_string(),
            max_age: 86400, // 24 hours
            // SECURITY: HttpOnly prevents JavaScript access (XSS protection)
            http_only: true,
            // SECURITY: Secure flag enforces HTTPS-only transmission
            secure: true,
            // SECURITY: SameSite=None is required because the hosted verification
            // flow is cross-origin (the verifier's site embeds provii-agegate which
            // communicates with the hosted backend on a different origin). The
            // Secure flag (enforced by __Host- prefix) ensures cookies are only
            // sent over HTTPS, mitigating the weaker CSRF posture. Additional
            // CSRF protection comes from PKCE on redeem and Origin validation.
            same_site: SameSitePolicy::None,
        }
    }
}

impl CookieConfig {
    /// Create a new cookie configuration with secure defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the cookie name.
    pub fn with_name(mut self, name: String) -> Self {
        self.name = name;
        self
    }

    /// Set an explicit Domain attribute. Incompatible with the `__Host-` prefix.
    pub fn with_domain(mut self, domain: String) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Set the Max-Age in seconds.
    pub fn with_max_age(mut self, max_age: u64) -> Self {
        self.max_age = max_age;
        self
    }

    /// Set the SameSite policy.
    pub fn with_same_site(mut self, same_site: SameSitePolicy) -> Self {
        self.same_site = same_site;
        self
    }
}

/// Returns `true` if every byte of `value` is in the cookie-value safe set
/// defined by RFC 6265 section 4.1.1: visible ASCII (0x21..=0x7E) excluding
/// semicolons, commas, spaces, backslashes, and double-quotes.
///
/// SECURITY: Rejecting characters outside this set prevents header injection
/// (CR/LF) and attribute injection (semicolons) in Set-Cookie values.
fn is_cookie_value_safe(value: &str) -> bool {
    value
        .bytes()
        .all(|b| matches!(b, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E))
}

/// Generate a Set-Cookie header value for an HMAC-signed session token.
///
/// Formats the cookie with all configured security attributes. When the
/// `__Host-` prefix is used, `config.domain` must be `None`, `config.path`
/// must be `"/"`, and `config.secure` must be `true`, or the browser will
/// silently reject the cookie.
///
/// # Arguments
///
/// * `token` - The HMAC-signed session token to store in the cookie
/// * `config` - Cookie configuration
///
/// # Returns
///
/// A complete Set-Cookie header value, or an empty deletion cookie if
/// the token contains characters outside the cookie-value safe set.
pub fn generate_session_cookie(token: &str, config: &CookieConfig) -> String {
    // SECURITY: VA-HOS-001 -- Reject tokens containing characters outside the
    // RFC 6265 cookie-value safe set. CR/LF would enable header injection;
    // semicolons would inject spurious cookie attributes. Rather than silently
    // stripping dangerous bytes (which would corrupt HMAC signatures), emit a
    // zero-Max-Age deletion cookie so the caller never sets an unsafe value.
    if !is_cookie_value_safe(token) {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!(
            "SECURITY: session token contains unsafe cookie-value characters; emitting deletion cookie"
        );
        return format!(
            "{}=invalid; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None",
            config.name
        );
    }
    // SECURITY: __Host- prefix invariant enforcement
    // RFC 6265bis requires: no Domain attribute, Secure=true, Path="/".
    // If the config violates these, fix in-place and log the violation
    // rather than returning an error (to avoid breaking callers).
    let config = if config.name.starts_with("__Host-") {
        let mut fixed = config.clone();
        let has_domain = fixed.domain.as_ref().is_some_and(|d| !d.is_empty());

        if has_domain {
            #[cfg(target_arch = "wasm32")]
            worker::console_error!(
                "__Host- cookie has Domain attribute set; removing to satisfy RFC 6265bis"
            );
            fixed.domain = None;
        }
        if !fixed.secure {
            #[cfg(target_arch = "wasm32")]
            worker::console_error!(
                "__Host- cookie has Secure=false; forcing Secure=true to satisfy RFC 6265bis"
            );
            fixed.secure = true;
        }
        if fixed.path != "/" {
            #[cfg(target_arch = "wasm32")]
            worker::console_error!(
                "__Host- cookie has Path!=/ (was {:?}); forcing Path=/ to satisfy RFC 6265bis",
                fixed.path
            );
            fixed.path = "/".to_string();
        }
        fixed
    } else {
        config.clone()
    };

    let mut parts = vec![format!("{}={}", config.name, token)];

    // SECURITY: __Host- prefix cookies MUST NOT have a Domain attribute.
    // An empty string is treated as absent to avoid accidental Domain emission.
    if let Some(domain) = &config.domain {
        if !domain.is_empty() {
            parts.push(format!("Domain={}", domain));
        }
    }

    // SECURITY: __Host- prefix requires Path=/
    parts.push(format!("Path={}", config.path));

    parts.push(format!("Max-Age={}", config.max_age));

    // SECURITY: HttpOnly prevents JavaScript access (XSS protection)
    if config.http_only {
        parts.push("HttpOnly".to_string());
    }

    // SECURITY: Secure flag enforces HTTPS-only transmission
    if config.secure {
        parts.push("Secure".to_string());
    }

    // SECURITY: SameSite attribute provides CSRF protection
    parts.push(format!("SameSite={}", config.same_site));

    parts.join("; ")
}

/// Parse a Cookie header and extract a named cookie value.
///
/// # Security
///
/// The `cookie_header` comes from the HTTP request and is attacker-controlled
/// input. This function performs only safe string splitting; no indexing into
/// computed offsets, no panicking paths. Callers must validate the returned
/// value before using it as a session token.
///
/// # Arguments
///
/// * `cookie_header` - The raw Cookie header value (attacker-controlled)
/// * `name` - The cookie name to look up
///
/// # Returns
///
/// The cookie value if present, or `None`.
pub fn parse_cookie(cookie_header: &str, name: &str) -> Option<String> {
    // SECURITY: Cookie parsing on attacker-controlled input. Uses only
    // safe iterator-based splitting; no index arithmetic.
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some((key, value)) = trimmed.split_once('=') {
            if key == name {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_cookie_config() {
        let config = CookieConfig::default();
        assert_eq!(config.name, "__Host-session");
        assert_eq!(config.domain, None); // Required for __Host- prefix
        assert_eq!(config.path, "/"); // Required for __Host- prefix
        assert_eq!(config.max_age, 86400);
        assert!(config.http_only);
        assert!(config.secure); // Required for __Host- prefix
        assert_eq!(config.same_site, SameSitePolicy::None); // Required for cross-origin hosted flow
    }

    #[test]
    fn test_cookie_config_builder() {
        let config = CookieConfig::new()
            .with_name("custom_session".to_string())
            .with_domain(".example.com".to_string())
            .with_max_age(7200)
            .with_same_site(SameSitePolicy::Strict);

        assert_eq!(config.name, "custom_session");
        assert_eq!(config.domain, Some(".example.com".to_string()));
        assert_eq!(config.max_age, 7200);
        assert_eq!(config.same_site, SameSitePolicy::Strict);
    }

    #[test]
    fn test_generate_session_cookie_with_host_prefix() {
        // Test __Host- prefix cookie (no domain attribute)
        let config = CookieConfig::new()
            .with_name("__Host-session".to_string())
            .with_max_age(3600)
            .with_same_site(SameSitePolicy::Strict);

        let header = generate_session_cookie("test-token-123", &config);

        assert!(header.contains("__Host-session=test-token-123"));
        assert!(!header.contains("Domain=")); // No Domain for __Host- prefix
        assert!(header.contains("Path=/"));
        assert!(header.contains("Max-Age=3600"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Strict"));
    }

    #[test]
    fn test_generate_session_cookie_with_domain() {
        // Test regular cookie with domain
        let config = CookieConfig::new()
            .with_name("regular_session".to_string())
            .with_domain(".provii.app".to_string())
            .with_max_age(3600)
            .with_same_site(SameSitePolicy::Lax);

        let header = generate_session_cookie("test-token-123", &config);

        assert!(header.contains("regular_session=test-token-123"));
        assert!(header.contains("Domain=.provii.app"));
        assert!(header.contains("Path=/"));
        assert!(header.contains("Max-Age=3600"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));
    }

    #[test]
    fn test_generate_session_cookie_no_domain() {
        let config = CookieConfig::new().with_max_age(7200);

        let header = generate_session_cookie("token", &config);

        assert!(header.contains("__Host-session=token"));
        assert!(!header.contains("Domain=")); // No Domain for __Host- prefix
        assert!(header.contains("Max-Age=7200"));
    }

    #[test]
    fn test_generate_session_cookie_empty_domain() {
        // Test that empty domain string is treated as None (for __Host- prefix)
        let config = CookieConfig::new()
            .with_name("__Host-session".to_string())
            .with_domain("".to_string())
            .with_max_age(3600);

        let header = generate_session_cookie("token", &config);

        assert!(header.contains("__Host-session=token"));
        assert!(!header.contains("Domain=")); // Empty domain should not add Domain attribute
        assert!(header.contains("Path=/"));
        assert!(header.contains("Secure"));
    }

    #[test]
    fn test_generate_session_cookie_strict() {
        let config = CookieConfig::new().with_same_site(SameSitePolicy::Strict);

        let header = generate_session_cookie("token", &config);
        assert!(header.contains("SameSite=Strict"));
    }

    #[test]
    fn test_generate_session_cookie_none() {
        let config = CookieConfig::new().with_same_site(SameSitePolicy::None);

        let header = generate_session_cookie("token", &config);
        assert!(header.contains("SameSite=None"));
    }

    #[test]
    fn test_parse_cookie_found() {
        let cookie_header = "session=abc123; other=value; provii_session=xyz789";
        let result = parse_cookie(cookie_header, "provii_session");
        assert_eq!(result, Some("xyz789".to_string()));
    }

    #[test]
    fn test_parse_cookie_first() {
        let cookie_header = "provii_session=first; other=second";
        let result = parse_cookie(cookie_header, "provii_session");
        assert_eq!(result, Some("first".to_string()));
    }

    #[test]
    fn test_parse_cookie_not_found() {
        let cookie_header = "session=abc123; other=value";
        let result = parse_cookie(cookie_header, "provii_session");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_cookie_empty() {
        let cookie_header = "";
        let result = parse_cookie(cookie_header, "provii_session");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_cookie_with_spaces() {
        let cookie_header = "provii_session=token123 ; other=value";
        let result = parse_cookie(cookie_header, "provii_session");
        assert_eq!(result, Some("token123".to_string()));
    }

    #[test]
    fn test_same_site_policy_display() {
        assert_eq!(format!("{}", SameSitePolicy::Lax), "Lax");
        assert_eq!(format!("{}", SameSitePolicy::Strict), "Strict");
        assert_eq!(format!("{}", SameSitePolicy::None), "None");
    }

    #[test]
    fn test_parse_cookie_with_host_prefix() {
        let cookie_header = "__Host-session=abc123; other=value";
        let result = parse_cookie(cookie_header, "__Host-session");
        assert_eq!(result, Some("abc123".to_string()));
    }

    #[test]
    fn test_parse_cookie_value_with_equals() {
        // Cookie values can contain '=' (e.g. base64 tokens)
        let cookie_header = "__Host-session=abc=123=; other=value";
        let result = parse_cookie(cookie_header, "__Host-session");
        assert_eq!(result, Some("abc=123=".to_string()));
    }

    #[test]
    fn test_host_prefix_removes_domain() {
        let config = CookieConfig {
            name: "__Host-session".to_string(),
            domain: Some(".example.com".to_string()),
            path: "/".to_string(),
            max_age: 3600,
            http_only: true,
            secure: true,
            same_site: SameSitePolicy::Strict,
        };
        let header = generate_session_cookie("tok", &config);
        assert!(
            !header.contains("Domain="),
            "Domain must be stripped for __Host- prefix"
        );
        assert!(header.contains("Secure"));
        assert!(header.contains("Path=/"));
    }

    #[test]
    fn test_host_prefix_forces_secure() {
        let config = CookieConfig {
            name: "__Host-session".to_string(),
            domain: None,
            path: "/".to_string(),
            max_age: 3600,
            http_only: true,
            secure: false,
            same_site: SameSitePolicy::Strict,
        };
        let header = generate_session_cookie("tok", &config);
        assert!(
            header.contains("Secure"),
            "Secure must be forced for __Host- prefix"
        );
    }

    #[test]
    fn test_host_prefix_forces_root_path() {
        let config = CookieConfig {
            name: "__Host-session".to_string(),
            domain: None,
            path: "/admin".to_string(),
            max_age: 3600,
            http_only: true,
            secure: true,
            same_site: SameSitePolicy::Strict,
        };
        let header = generate_session_cookie("tok", &config);
        assert!(
            header.contains("Path=/;") || header.contains("Path=/\n") || header.ends_with("Path=/"),
            "Path must be forced to / for __Host- prefix, got: {}",
            header
        );
        assert!(!header.contains("Path=/admin"));
    }

    #[test]
    fn test_host_prefix_fixes_all_violations() {
        let config = CookieConfig {
            name: "__Host-session".to_string(),
            domain: Some(".evil.com".to_string()),
            path: "/sub".to_string(),
            max_age: 3600,
            http_only: true,
            secure: false,
            same_site: SameSitePolicy::Strict,
        };
        let header = generate_session_cookie("tok", &config);
        assert!(!header.contains("Domain="));
        assert!(header.contains("Secure"));
        assert!(!header.contains("Path=/sub"));
    }

    #[test]
    fn test_non_host_prefix_allows_domain() {
        // Non-__Host- cookies should NOT have enforcement applied
        let config = CookieConfig {
            name: "regular_session".to_string(),
            domain: Some(".example.com".to_string()),
            path: "/app".to_string(),
            max_age: 3600,
            http_only: true,
            secure: false,
            same_site: SameSitePolicy::Lax,
        };
        let header = generate_session_cookie("tok", &config);
        assert!(header.contains("Domain=.example.com"));
        assert!(header.contains("Path=/app"));
        assert!(!header.contains("Secure"));
    }

    // --- New coverage tests below ---

    #[test]
    fn test_cookie_config_new_equals_default() {
        let from_new = CookieConfig::new();
        let from_default = CookieConfig::default();
        assert_eq!(from_new.name, from_default.name);
        assert_eq!(from_new.domain, from_default.domain);
        assert_eq!(from_new.path, from_default.path);
        assert_eq!(from_new.max_age, from_default.max_age);
        assert_eq!(from_new.http_only, from_default.http_only);
        assert_eq!(from_new.secure, from_default.secure);
        assert_eq!(from_new.same_site, from_default.same_site);
    }

    #[test]
    fn test_generate_cookie_header_format() {
        // Verify the header is semicolon-space delimited
        let config = CookieConfig::default();
        let header = generate_session_cookie("tok", &config);
        let parts: Vec<&str> = header.split("; ").collect();

        // Name=value, Path=/, Max-Age=86400, HttpOnly, Secure, SameSite=None
        assert_eq!(parts.len(), 6, "Expected 6 parts, got: {:?}", parts);
        assert_eq!(parts[0], "__Host-session=tok");
        assert_eq!(parts[1], "Path=/");
        assert_eq!(parts[2], "Max-Age=86400");
        assert_eq!(parts[3], "HttpOnly");
        assert_eq!(parts[4], "Secure");
        assert_eq!(parts[5], "SameSite=None");
    }

    #[test]
    fn test_generate_cookie_with_domain_header_format() {
        let config = CookieConfig {
            name: "sess".to_string(),
            domain: Some(".example.com".to_string()),
            path: "/app".to_string(),
            max_age: 100,
            http_only: true,
            secure: true,
            same_site: SameSitePolicy::Lax,
        };
        let header = generate_session_cookie("val", &config);
        let parts: Vec<&str> = header.split("; ").collect();

        // Name=value, Domain=..., Path=/app, Max-Age=100, HttpOnly, Secure, SameSite=Lax
        assert_eq!(
            parts.len(),
            7,
            "Expected 7 parts with domain, got: {:?}",
            parts
        );
        assert_eq!(parts[0], "sess=val");
        assert_eq!(parts[1], "Domain=.example.com");
    }

    #[test]
    fn test_generate_cookie_http_only_false() {
        let config = CookieConfig {
            name: "sess".to_string(),
            domain: None,
            path: "/".to_string(),
            max_age: 100,
            http_only: false,
            secure: false,
            same_site: SameSitePolicy::Lax,
        };
        let header = generate_session_cookie("tok", &config);
        assert!(
            !header.contains("HttpOnly"),
            "HttpOnly should be absent when http_only=false"
        );
        assert!(
            !header.contains("Secure"),
            "Secure should be absent when secure=false"
        );
    }

    #[test]
    fn test_generate_cookie_non_host_prefix_no_domain_skips_domain() {
        // Non-__Host- cookie with domain=None should not emit Domain=
        let config = CookieConfig {
            name: "regular".to_string(),
            domain: None,
            path: "/".to_string(),
            max_age: 100,
            http_only: true,
            secure: true,
            same_site: SameSitePolicy::Strict,
        };
        let header = generate_session_cookie("tok", &config);
        assert!(!header.contains("Domain="));
    }

    #[test]
    fn test_generate_cookie_non_host_prefix_empty_domain_skips_domain() {
        let config = CookieConfig {
            name: "regular".to_string(),
            domain: Some("".to_string()),
            path: "/".to_string(),
            max_age: 100,
            http_only: true,
            secure: true,
            same_site: SameSitePolicy::Strict,
        };
        let header = generate_session_cookie("tok", &config);
        assert!(
            !header.contains("Domain="),
            "Empty domain string should not emit Domain attribute"
        );
    }

    #[test]
    fn test_generate_cookie_max_age_zero() {
        // Max-Age=0 is used for cookie deletion
        let config = CookieConfig::new().with_max_age(0);
        let header = generate_session_cookie("tok", &config);
        assert!(header.contains("Max-Age=0"));
    }

    #[test]
    fn test_generate_cookie_token_with_special_chars() {
        // Tokens may contain base64url characters
        let config = CookieConfig::default();
        let header = generate_session_cookie("abc-DEF_123.456~789", &config);
        assert!(header.contains("__Host-session=abc-DEF_123.456~789"));
    }

    #[test]
    fn test_parse_cookie_single_cookie() {
        let result = parse_cookie("session=abc", "session");
        assert_eq!(result, Some("abc".to_string()));
    }

    #[test]
    fn test_parse_cookie_multiple_same_name_returns_first() {
        // If the same name appears twice, first match wins
        let header = "tok=first; tok=second";
        let result = parse_cookie(header, "tok");
        assert_eq!(result, Some("first".to_string()));
    }

    #[test]
    fn test_parse_cookie_leading_trailing_whitespace() {
        let header = "  session=abc  ;  other=val  ";
        assert_eq!(parse_cookie(header, "session"), Some("abc".to_string()));
        assert_eq!(parse_cookie(header, "other"), Some("val".to_string()));
    }

    #[test]
    fn test_parse_cookie_no_value() {
        // A cookie with no value (just a key with =)
        let header = "session=; other=val";
        assert_eq!(parse_cookie(header, "session"), Some("".to_string()));
    }

    #[test]
    fn test_parse_cookie_partial_name_no_match() {
        // "session_token" should not match "session"
        let header = "session_token=abc";
        assert_eq!(parse_cookie(header, "session"), None);
    }

    #[test]
    fn test_parse_cookie_prefix_name_no_match() {
        // "sess" should not match "session"
        let header = "session=abc";
        assert_eq!(parse_cookie(header, "sess"), None);
    }

    #[test]
    fn test_parse_cookie_no_equals_sign() {
        // Malformed cookie part with no equals sign
        let header = "noequals; session=abc";
        assert_eq!(parse_cookie(header, "session"), Some("abc".to_string()));
        assert_eq!(parse_cookie(header, "noequals"), None);
    }

    #[test]
    fn test_parse_cookie_value_with_multiple_equals() {
        // base64 tokens often have trailing = padding
        let header = "__Host-session=dGVzdA==; other=val";
        let result = parse_cookie(header, "__Host-session");
        assert_eq!(result, Some("dGVzdA==".to_string()));
    }

    #[test]
    fn test_same_site_policy_equality() {
        assert_eq!(SameSitePolicy::Lax, SameSitePolicy::Lax);
        assert_ne!(SameSitePolicy::Lax, SameSitePolicy::Strict);
        assert_ne!(SameSitePolicy::Strict, SameSitePolicy::None);
        assert_ne!(SameSitePolicy::Lax, SameSitePolicy::None);
    }

    #[test]
    fn test_same_site_policy_clone() {
        let policy = SameSitePolicy::Strict;
        let cloned = policy;
        assert_eq!(policy, cloned);
    }

    #[test]
    fn test_cookie_config_debug() {
        let config = CookieConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("__Host-session"));
        assert!(debug.contains("CookieConfig"));
    }

    #[test]
    fn test_host_prefix_combined_all_three_violations() {
        // Domain set, Secure false, Path not "/" -- all three should be fixed
        let config = CookieConfig {
            name: "__Host-test".to_string(),
            domain: Some(".bad.com".to_string()),
            path: "/sub/path".to_string(),
            max_age: 60,
            http_only: true,
            secure: false,
            same_site: SameSitePolicy::Lax,
        };
        let header = generate_session_cookie("v", &config);
        assert!(!header.contains("Domain="));
        assert!(header.contains("Secure"));
        assert!(header.contains("Path=/;") || header.ends_with("Path=/"));
        assert!(!header.contains("/sub/path"));
        assert!(header.contains("__Host-test=v"));
    }

    #[test]
    fn test_with_same_site_all_variants() {
        let lax = CookieConfig::new().with_same_site(SameSitePolicy::Lax);
        assert_eq!(lax.same_site, SameSitePolicy::Lax);

        let strict = CookieConfig::new().with_same_site(SameSitePolicy::Strict);
        assert_eq!(strict.same_site, SameSitePolicy::Strict);

        let none = CookieConfig::new().with_same_site(SameSitePolicy::None);
        assert_eq!(none.same_site, SameSitePolicy::None);
    }

    #[test]
    fn test_generate_cookie_large_max_age() {
        let config = CookieConfig::new().with_max_age(u64::MAX);
        let header = generate_session_cookie("tok", &config);
        let expected = format!("Max-Age={}", u64::MAX);
        assert!(header.contains(&expected));
    }

    // ── VA-HOS-001: Cookie token sanitisation tests ────────────────────

    #[test]
    fn test_is_cookie_value_safe_valid_token() {
        assert!(is_cookie_value_safe("abc-DEF_123.456~789"));
        assert!(is_cookie_value_safe("dGVzdA"));
    }

    #[test]
    fn test_is_cookie_value_safe_rejects_crlf() {
        assert!(!is_cookie_value_safe("token\r\nSet-Cookie: evil=1"));
        assert!(!is_cookie_value_safe("token\nevil"));
        assert!(!is_cookie_value_safe("token\revil"));
    }

    #[test]
    fn test_is_cookie_value_safe_rejects_semicolon() {
        assert!(!is_cookie_value_safe("token; Path=/evil"));
    }

    #[test]
    fn test_is_cookie_value_safe_rejects_space() {
        assert!(!is_cookie_value_safe("token value"));
    }

    #[test]
    fn test_is_cookie_value_safe_rejects_comma() {
        assert!(!is_cookie_value_safe("token,value"));
    }

    #[test]
    fn test_is_cookie_value_safe_rejects_backslash() {
        assert!(!is_cookie_value_safe("token\\value"));
    }

    #[test]
    fn test_is_cookie_value_safe_rejects_double_quote() {
        assert!(!is_cookie_value_safe("token\"value"));
    }

    #[test]
    fn test_is_cookie_value_safe_empty() {
        assert!(is_cookie_value_safe(""));
    }

    #[test]
    fn test_generate_cookie_rejects_unsafe_token() {
        let config = CookieConfig::default();
        let header = generate_session_cookie("evil\r\nSet-Cookie: hack=1", &config);
        assert!(
            header.contains("Max-Age=0"),
            "unsafe token should emit deletion cookie"
        );
        assert!(
            header.contains("invalid"),
            "unsafe token should emit 'invalid' value"
        );
        assert!(!header.contains("evil"));
    }

    #[test]
    fn test_generate_cookie_rejects_semicolon_in_token() {
        let config = CookieConfig::default();
        let header = generate_session_cookie("token; Domain=evil.com", &config);
        assert!(header.contains("Max-Age=0"));
    }
}
