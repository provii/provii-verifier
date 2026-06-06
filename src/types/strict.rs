// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Strictly validated type wrappers used by the API.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use schemars::JsonSchema;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroize;

/// Base64url-encoded wrapper around a 32-byte array.
#[derive(Clone, Hash, JsonSchema)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct B64Url32(#[schemars(with = "String")] pub [u8; 32]);

impl fmt::Debug for B64Url32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("B64Url32(***redacted***)")
    }
}

impl Drop for B64Url32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl B64Url32 {
    /// Construct from a raw 32-byte array.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the inner 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for B64Url32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for B64Url32 {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for B64Url32 {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        // ACCEPT: serde intermediate String; dropped by runtime, cannot zeroize (upstream limitation).
        let s = String::deserialize(de)?;

        // Check length and characters.
        if s.len() != 43
            || !s
                .bytes()
                .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
        {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(&s),
                &"base64url string of exactly 43 characters",
            ));
        }

        let decoded = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(&s), &"valid base64url"))?;

        if decoded.len() != 32 {
            return Err(de::Error::invalid_length(decoded.len(), &"32 bytes"));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        Ok(Self(arr))
    }
}

/// Base64url-encoded wrapper around a 192-byte array.
#[derive(Clone, Hash, JsonSchema)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct B64Url192(#[schemars(with = "String")] pub [u8; 192]);

impl fmt::Debug for B64Url192 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("B64Url192(***redacted***)")
    }
}

impl Drop for B64Url192 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl B64Url192 {
    /// Construct from a raw 192-byte array.
    pub fn new(bytes: [u8; 192]) -> Self {
        Self(bytes)
    }

    /// Borrow the inner 192-byte array.
    pub fn as_bytes(&self) -> &[u8; 192] {
        &self.0
    }
}

impl fmt::Display for B64Url192 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for B64Url192 {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for B64Url192 {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        // ACCEPT: serde intermediate String; dropped by runtime, cannot zeroize (upstream limitation).
        let s = String::deserialize(de)?;

        // Check length and characters.
        if s.len() != 256
            || !s
                .bytes()
                .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
        {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(&s),
                &"base64url string of exactly 256 characters",
            ));
        }

        let decoded = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(&s), &"valid base64url"))?;

        if decoded.len() != 192 {
            return Err(de::Error::invalid_length(decoded.len(), &"192 bytes"));
        }

        let mut arr = [0u8; 192];
        arr.copy_from_slice(&decoded);
        Ok(Self(arr))
    }
}

/// UUID wrapper constrained to version 4 values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, JsonSchema)]
pub struct UuidV4(pub Uuid);

impl<'de> Deserialize<'de> for UuidV4 {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        let u = Uuid::parse_str(&s)
            .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(&s), &"valid uuid"))?;
        if u.get_version_num() != 4 {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(&s),
                &"uuid version 4",
            ));
        }
        Ok(UuidV4(u))
    }
}

impl fmt::Display for UuidV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 12-digit numeric short code for accessibility (manual entry).
/// Displayed as XXXX XXXX XXXX but stored as single 12-character string.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, JsonSchema)]
pub struct ShortCode(String);

impl<'de> Deserialize<'de> for ShortCode {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;

        // Remove spaces for validation (allows both "XXXX XXXX XXXX" and "XXXXXXXXXXXX")
        let normalized: String = s.chars().filter(|c| !c.is_whitespace()).collect();

        if normalized.len() != 12 {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(&s),
                &"12-digit numeric code (with or without spaces)",
            ));
        }

        if !normalized.chars().all(|c| c.is_ascii_digit()) {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(&s),
                &"numeric characters only (0-9)",
            ));
        }

        Ok(Self(normalized))
    }
}

impl ShortCode {
    /// Create a new ShortCode, removing any whitespace
    pub fn new(s: &str) -> Result<Self, String> {
        let normalized: String = s.chars().filter(|c| !c.is_whitespace()).collect();

        if normalized.len() != 12 {
            return Err(format!(
                "short code must be exactly 12 digits, got {}",
                normalized.len()
            ));
        }

        if !normalized.chars().all(|c| c.is_ascii_digit()) {
            return Err("short code must contain only numeric digits (0-9)".to_string());
        }

        Ok(Self(normalized))
    }

    /// Get the code as a 12-character string (no spaces)
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Format with spaces as XXXX XXXX XXXX for display
    pub fn display_formatted(&self) -> String {
        // Constructor guarantees exactly 12 ASCII digits, so these slices are safe.
        let p1 = self.0.get(0..4).unwrap_or("");
        let p2 = self.0.get(4..8).unwrap_or("");
        let p3 = self.0.get(8..12).unwrap_or("");
        format!("{} {} {}", p1, p2, p3)
    }
}

impl fmt::Display for ShortCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// PKCE `code_verifier` value constrained to the RFC 7636 character set.
///
/// SECURITY: The code verifier is a high-entropy secret used exactly once.
/// It is zeroized on drop and redacted in Debug output.
#[derive(Clone, Hash, Serialize, JsonSchema)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PkceCodeVerifier(String);

impl fmt::Debug for PkceCodeVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PkceCodeVerifier(***redacted***)")
    }
}

impl Drop for PkceCodeVerifier {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> Deserialize<'de> for PkceCodeVerifier {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        // SECURITY: Serde produces a temporary String here. It is moved into Self
        // on success and zeroized via Drop. On validation failure the temporary is
        // dropped by the runtime; we cannot zeroize it because serde owns the error path.
        // ACCEPT: serde intermediate String on error path (upstream limitation).
        let s = String::deserialize(de)?;
        let len = s.len();
        if !(43..=128).contains(&len)
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        {
            return Err(de::Error::invalid_value(
                de::Unexpected::Other("invalid_code_verifier"),
                &"RFC7636 code_verifier (43..128 chars, unreserved)",
            ));
        }
        Ok(Self(s))
    }
}

impl PkceCodeVerifier {
    /// Borrow the inner code verifier string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Supported PKCE code challenge methods.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum PkceMethod {
    #[default]
    S256,
}

/// Strongly typed wrapper around a cutoff expressed in epoch days.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CutoffDays(i32);

impl CutoffDays {
    /// Lower bound (negative values represent dates after today, i.e. future cutoffs).
    pub const MIN: i32 = -25_000;
    /// Upper bound (~150 years).
    pub const MAX: i32 = 54_750;
    /// Return the inner value.
    pub fn get(self) -> i32 {
        self.0
    }

    /// Construct a new `CutoffDays`, returning an error when out of range.
    pub fn new(v: i32) -> Result<Self, String> {
        if !(Self::MIN..=Self::MAX).contains(&v) {
            return Err(format!(
                "cutoff_days {} out of range [{}, {}]",
                v,
                Self::MIN,
                Self::MAX
            ));
        }
        Ok(Self(v))
    }
}

impl<'de> Deserialize<'de> for CutoffDays {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let v = i32::deserialize(de)?;
        Self::new(v)
            .map_err(|e| de::Error::invalid_value(de::Unexpected::Signed(v as i64), &e.as_str()))
    }
}

/// Non-zero verifying key identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct VkId(u32);

impl<'de> Deserialize<'de> for VkId {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let v = u32::deserialize(de)?;
        if v == 0 {
            return Err(de::Error::invalid_value(
                de::Unexpected::Unsigned(v as u64),
                &"non-zero verifying_key_id",
            ));
        }
        Ok(Self(v))
    }
}

impl VkId {
    /// Return the inner value.
    pub fn get(self) -> u32 {
        self.0
    }

    /// Construct from a `u32`, returning `None` when zero.
    pub fn new(v: u32) -> Option<Self> {
        if v > 0 {
            Some(Self(v))
        } else {
            None
        }
    }
}

/// TTL for a challenge, clamped to `[MIN, MAX]` on construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ExpiresIn(u64);

impl ExpiresIn {
    /// Minimum allowed TTL in seconds.
    ///
    /// Cloudflare Workers KV's `.expiration_ttl()` rejects values below 60s,
    /// and the `/v1/challenge` route writes a `code:<short>` KV mapping with
    /// this ttl. Below-60 values made the write fail and surface as a generic
    /// 500. Match the lower bound exposed by the runtime.
    pub const MIN: u64 = 60;
    /// Maximum allowed TTL in seconds.
    pub const MAX: u64 = 300;

    /// Return the inner value.
    pub fn get(self) -> u64 {
        self.0
    }

    /// Construct a new `ExpiresIn`, clamping the value to `[MIN, MAX]`.
    pub fn new(v: u64) -> Self {
        Self(v.clamp(Self::MIN, Self::MAX))
    }
}

impl Default for ExpiresIn {
    fn default() -> Self {
        Self(300)
    }
}

impl<'de> Deserialize<'de> for ExpiresIn {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let v = u64::deserialize(de)?;
        Ok(Self::new(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    B64Url32 TESTS                                         */
    /* ========================================================================== */

    #[test]
    fn test_b64url32_new() {
        let bytes = [42u8; 32];
        let b64 = B64Url32::new(bytes);
        assert_eq!(b64.as_bytes(), &bytes);
    }

    #[test]
    fn test_b64url32_display() {
        let bytes = [0u8; 32];
        let b64 = B64Url32::new(bytes);
        let s = b64.to_string();
        assert_eq!(s, "[REDACTED]"); // Display trait redacts secrets
    }

    #[test]
    fn test_b64url32_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = [1u8; 32];
        let b64 = B64Url32::new(bytes);
        let json = serde_json::to_string(&b64)?;
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
        Ok(())
    }

    #[test]
    fn test_b64url32_deserialize_valid() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = [2u8; 32];
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        let json = format!("\"{}\"", encoded);
        let b64: B64Url32 = serde_json::from_str(&json)?;
        assert_eq!(b64.as_bytes(), &bytes);
        Ok(())
    }

    #[test]
    fn test_b64url32_deserialize_invalid_length() {
        let json = "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\""; // 44 chars
        let result: Result<B64Url32, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url32_deserialize_invalid_chars() {
        let json = "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+\""; // + not allowed
        let result: Result<B64Url32, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url32_clone_eq_hash() {
        let b1 = B64Url32::new([3u8; 32]);
        let b2 = b1.clone();
        assert_eq!(b1, b2);
    }

    /* ========================================================================== */
    /*                    B64Url192 TESTS                                        */
    /* ========================================================================== */

    #[test]
    fn test_b64url192_new() {
        let bytes = [42u8; 192];
        let b64 = B64Url192::new(bytes);
        assert_eq!(b64.as_bytes(), &bytes);
    }

    #[test]
    fn test_b64url192_display() {
        let bytes = [0u8; 192];
        let b64 = B64Url192::new(bytes);
        let s = b64.to_string();
        assert_eq!(s, "[REDACTED]"); // Display trait redacts secrets
    }

    #[test]
    fn test_b64url192_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = [1u8; 192];
        let b64 = B64Url192::new(bytes);
        let json = serde_json::to_string(&b64)?;
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
        Ok(())
    }

    #[test]
    fn test_b64url192_deserialize_valid() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = [2u8; 192];
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        let json = format!("\"{}\"", encoded);
        let b64: B64Url192 = serde_json::from_str(&json)?;
        assert_eq!(b64.as_bytes(), &bytes);
        Ok(())
    }

    #[test]
    fn test_b64url192_deserialize_invalid_length() {
        let json = format!("\"{}\"", "A".repeat(255)); // 255 chars
        let result: Result<B64Url192, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    UuidV4 TESTS                                           */
    /* ========================================================================== */

    #[test]
    fn test_uuidv4_deserialize_valid() -> Result<(), Box<dyn std::error::Error>> {
        let uuid = Uuid::new_v4();
        let json = format!("\"{}\"", uuid);
        let wrapped: UuidV4 = serde_json::from_str(&json)?;
        assert_eq!(wrapped.0, uuid);
        Ok(())
    }

    #[test]
    fn test_uuidv4_deserialize_invalid_version() {
        // UUID v1 (time-based)
        let json = "\"550e8400-e29b-11d4-a716-446655440000\"";
        let result: Result<UuidV4, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_uuidv4_deserialize_malformed() {
        let json = "\"not-a-uuid\"";
        let result: Result<UuidV4, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_uuidv4_display() {
        let uuid = Uuid::new_v4();
        let wrapped = UuidV4(uuid);
        assert_eq!(wrapped.to_string(), uuid.to_string());
    }

    #[test]
    fn test_uuidv4_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let uuid = Uuid::new_v4();
        let wrapped = UuidV4(uuid);
        let json = serde_json::to_string(&wrapped)?;
        assert!(json.contains(&uuid.to_string()));
        Ok(())
    }

    /* ========================================================================== */
    /*                    ShortCode TESTS                                        */
    /* ========================================================================== */

    #[test]
    fn test_shortcode_new_valid() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new("123456789012")?;
        assert_eq!(code.as_str(), "123456789012");
        Ok(())
    }

    #[test]
    fn test_shortcode_new_with_spaces() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new("1234 5678 9012")?;
        assert_eq!(code.as_str(), "123456789012");
        Ok(())
    }

    #[test]
    fn test_shortcode_new_too_short() {
        let result = ShortCode::new("12345678901");
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_new_too_long() {
        let result = ShortCode::new("1234567890123");
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_new_non_numeric() {
        let result = ShortCode::new("12345678901a");
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_deserialize_valid() -> Result<(), Box<dyn std::error::Error>> {
        let json = "\"123456789012\"";
        let code: ShortCode = serde_json::from_str(json)?;
        assert_eq!(code.as_str(), "123456789012");
        Ok(())
    }

    #[test]
    fn test_shortcode_deserialize_with_spaces() -> Result<(), Box<dyn std::error::Error>> {
        let json = "\"1234 5678 9012\"";
        let code: ShortCode = serde_json::from_str(json)?;
        assert_eq!(code.as_str(), "123456789012");
        Ok(())
    }

    #[test]
    fn test_shortcode_deserialize_invalid_length() {
        let json = "\"12345\"";
        let result: Result<ShortCode, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_deserialize_non_numeric() {
        let json = "\"abcd5678901\"";
        let result: Result<ShortCode, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_display_formatted() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new("123456789012")?;
        assert_eq!(code.display_formatted(), "1234 5678 9012");
        Ok(())
    }

    #[test]
    fn test_shortcode_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new("987654321098")?;
        let json = serde_json::to_string(&code)?;
        assert_eq!(json, "\"987654321098\"");
        Ok(())
    }

    #[test]
    fn test_shortcode_display() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new("111222333444")?;
        assert_eq!(code.to_string(), "111222333444");
        Ok(())
    }

    #[test]
    fn test_shortcode_clone_eq_hash() -> Result<(), Box<dyn std::error::Error>> {
        let c1 = ShortCode::new("555666777888")?;
        let c2 = c1.clone();
        assert_eq!(c1, c2);
        Ok(())
    }

    /* ========================================================================== */
    /*                    PkceCodeVerifier TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_pkce_verifier_deserialize_valid_min() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = "a".repeat(43);
        let json = format!("\"{}\"", verifier);
        let result: PkceCodeVerifier = serde_json::from_str(&json)?;
        assert_eq!(result.as_str(), verifier);
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_deserialize_valid_max() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = "a".repeat(128);
        let json = format!("\"{}\"", verifier);
        let result: PkceCodeVerifier = serde_json::from_str(&json)?;
        assert_eq!(result.as_str(), verifier);
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_deserialize_too_short() {
        let json = format!("\"{}\"", "a".repeat(42));
        let result: Result<PkceCodeVerifier, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_verifier_deserialize_too_long() {
        let json = format!("\"{}\"", "a".repeat(129));
        let result: Result<PkceCodeVerifier, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_verifier_deserialize_invalid_chars() {
        let json = format!("\"{}+\"", "a".repeat(42)); // + not allowed
        let result: Result<PkceCodeVerifier, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_verifier_allowed_special_chars() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = format!("{}-._~", "a".repeat(39));
        let json = format!("\"{}\"", verifier);
        let result: PkceCodeVerifier = serde_json::from_str(&json)?;
        assert_eq!(result.as_str(), verifier);
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = "a".repeat(50);
        let json_in = format!("\"{}\"", verifier);
        let parsed: PkceCodeVerifier = serde_json::from_str(&json_in)?;
        let json_out = serde_json::to_string(&parsed)?;
        assert!(json_out.contains(&verifier));
        Ok(())
    }

    /* ========================================================================== */
    /*                    PkceMethod TESTS                                       */
    /* ========================================================================== */

    #[test]
    fn test_pkce_method_default() {
        assert_eq!(PkceMethod::default(), PkceMethod::S256);
    }

    #[test]
    fn test_pkce_method_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let json = "\"S256\"";
        let method: PkceMethod = serde_json::from_str(json)?;
        assert_eq!(method, PkceMethod::S256);
        Ok(())
    }

    #[test]
    fn test_pkce_method_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&PkceMethod::S256)?;
        assert_eq!(json, "\"S256\"");
        Ok(())
    }

    /* ========================================================================== */
    /*                    CutoffDays TESTS                                       */
    /* ========================================================================== */

    #[test]
    fn test_cutoff_days_new_valid() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff = CutoffDays::new(6570)?; // ~18 years
        assert_eq!(cutoff.get(), 6570);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_min() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff = CutoffDays::new(CutoffDays::MIN)?;
        assert_eq!(cutoff.get(), CutoffDays::MIN);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_max() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff = CutoffDays::new(CutoffDays::MAX)?;
        assert_eq!(cutoff.get(), CutoffDays::MAX);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_below_min() {
        let result = CutoffDays::new(CutoffDays::MIN - 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_cutoff_days_new_above_max() {
        let result = CutoffDays::new(CutoffDays::MAX + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_cutoff_days_deserialize_valid() -> Result<(), Box<dyn std::error::Error>> {
        let json = "6570";
        let cutoff: CutoffDays = serde_json::from_str(json)?;
        assert_eq!(cutoff.get(), 6570);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_deserialize_invalid() {
        let json = "100000"; // Exceeds MAX of 54750
        let result: Result<CutoffDays, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_cutoff_days_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff = CutoffDays::new(7665)?; // ~21 years
        let json = serde_json::to_string(&cutoff)?;
        assert_eq!(json, "7665");
        Ok(())
    }

    /* ========================================================================== */
    /*                    VkId TESTS                                             */
    /* ========================================================================== */

    #[test]
    fn test_vkid_new_valid() -> Result<(), Box<dyn std::error::Error>> {
        let vkid = VkId::new(1).ok_or("VkId::new(1) returned None")?;
        assert_eq!(vkid.get(), 1);
        Ok(())
    }

    #[test]
    fn test_vkid_new_zero() {
        let result = VkId::new(0);
        assert!(result.is_none());
    }

    #[test]
    fn test_vkid_deserialize_valid() -> Result<(), Box<dyn std::error::Error>> {
        let json = "42";
        let vkid: VkId = serde_json::from_str(json)?;
        assert_eq!(vkid.get(), 42);
        Ok(())
    }

    #[test]
    fn test_vkid_deserialize_zero() {
        let json = "0";
        let result: Result<VkId, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_vkid_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let json = "123";
        let vkid: VkId = serde_json::from_str(json)?;
        let serialized = serde_json::to_string(&vkid)?;
        assert_eq!(serialized, "123");
        Ok(())
    }

    /* ========================================================================== */
    /*                    ExpiresIn TESTS                                        */
    /* ========================================================================== */

    #[test]
    fn test_expiresin_default() {
        assert_eq!(ExpiresIn::default().get(), 300);
    }

    #[test]
    fn test_expiresin_new_within_range() {
        let expires = ExpiresIn::new(60);
        assert_eq!(expires.get(), 60);
    }

    #[test]
    fn test_expiresin_new_below_min_clamped() {
        let expires = ExpiresIn::new(10); // Below MIN (60)
        assert_eq!(expires.get(), 60); // Clamped to MIN
    }

    #[test]
    fn test_expiresin_new_above_max_clamped() {
        let expires = ExpiresIn::new(500); // Above MAX (300)
        assert_eq!(expires.get(), 300); // Clamped to MAX
    }

    #[test]
    fn test_expiresin_new_zero_clamped() {
        let expires = ExpiresIn::new(0);
        assert_eq!(expires.get(), 60); // Clamped to MIN
    }

    #[test]
    fn test_expiresin_deserialize_valid() -> Result<(), Box<dyn std::error::Error>> {
        let json = "120";
        let expires: ExpiresIn = serde_json::from_str(json)?;
        assert_eq!(expires.get(), 120);
        Ok(())
    }

    #[test]
    fn test_expiresin_deserialize_clamped_low() -> Result<(), Box<dyn std::error::Error>> {
        let json = "15";
        let expires: ExpiresIn = serde_json::from_str(json)?;
        assert_eq!(expires.get(), 60);
        Ok(())
    }

    #[test]
    fn test_expiresin_deserialize_clamped_high() -> Result<(), Box<dyn std::error::Error>> {
        let json = "600";
        let expires: ExpiresIn = serde_json::from_str(json)?;
        assert_eq!(expires.get(), 300);
        Ok(())
    }

    #[test]
    fn test_expiresin_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let expires = ExpiresIn::new(180);
        let json = serde_json::to_string(&expires)?;
        assert_eq!(json, "180");
        Ok(())
    }

    /* ========================================================================== */
    /*                    B64Url32 Debug redaction TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_b64url32_debug_redacted() {
        let b64 = B64Url32::new([0xABu8; 32]);
        let debug = format!("{:?}", b64);
        assert_eq!(debug, "B64Url32(***redacted***)");
        // Raw bytes should NOT appear
        assert!(!debug.contains("171")); // 0xAB = 171
    }

    /* ========================================================================== */
    /*                    B64Url192 Debug redaction TESTS                        */
    /* ========================================================================== */

    #[test]
    fn test_b64url192_debug_redacted() {
        let b64 = B64Url192::new([0xCDu8; 192]);
        let debug = format!("{:?}", b64);
        assert_eq!(debug, "B64Url192(***redacted***)");
    }

    /* ========================================================================== */
    /*                    B64Url32 deserialize edge cases                        */
    /* ========================================================================== */

    #[test]
    fn test_b64url32_deserialize_too_short() {
        let json = format!("\"{}\"", "A".repeat(42));
        let result: Result<B64Url32, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url32_deserialize_padding_rejected() {
        // Standard base64 with padding should be rejected
        let json = "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"";
        let result: Result<B64Url32, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url32_deserialize_plus_rejected() {
        // + is standard base64, not url-safe
        let json = format!("\"{}+A\"", "A".repeat(41));
        let result: Result<B64Url32, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url32_deserialize_slash_rejected() {
        // / is standard base64, not url-safe
        let json = format!("\"{}/A\"", "A".repeat(41));
        let result: Result<B64Url32, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url32_roundtrip_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let b64 = B64Url32::new([0u8; 32]);
        let json = serde_json::to_string(&b64)?;
        let decoded: B64Url32 = serde_json::from_str(&json)?;
        assert_eq!(decoded.as_bytes(), &[0u8; 32]);
        Ok(())
    }

    #[test]
    fn test_b64url32_roundtrip_all_ff() -> Result<(), Box<dyn std::error::Error>> {
        let b64 = B64Url32::new([0xFFu8; 32]);
        let json = serde_json::to_string(&b64)?;
        let decoded: B64Url32 = serde_json::from_str(&json)?;
        assert_eq!(decoded.as_bytes(), &[0xFFu8; 32]);
        Ok(())
    }

    /* ========================================================================== */
    /*                    B64Url192 deserialize edge cases                       */
    /* ========================================================================== */

    #[test]
    fn test_b64url192_deserialize_too_long() {
        let json = format!("\"{}\"", "A".repeat(257));
        let result: Result<B64Url192, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url192_deserialize_plus_rejected() {
        let json = format!("\"{}+\"", "A".repeat(255));
        let result: Result<B64Url192, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url192_clone() {
        let b1 = B64Url192::new([7u8; 192]);
        let b2 = b1.clone();
        assert_eq!(b1, b2);
    }

    /* ========================================================================== */
    /*                    UuidV4 additional TESTS                                */
    /* ========================================================================== */

    #[test]
    fn test_uuidv4_clone_copy() {
        let u1 = UuidV4(Uuid::new_v4());
        let u2 = u1; // Copy
        let u3 = u1; // Copy again
        assert_eq!(u2, u3);
    }

    #[test]
    fn test_uuidv4_hash() {
        use std::collections::HashSet;
        let u1 = UuidV4(Uuid::new_v4());
        let u2 = UuidV4(Uuid::new_v4());
        let mut set = HashSet::new();
        set.insert(u1);
        set.insert(u2);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_uuidv4_deserialize_nil_rejected() {
        // Nil UUID is version "nil", not v4
        let json = "\"00000000-0000-0000-0000-000000000000\"";
        let result: Result<UuidV4, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_uuidv4_serialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let uuid = Uuid::new_v4();
        let wrapped = UuidV4(uuid);
        let json = serde_json::to_string(&wrapped)?;
        let decoded: UuidV4 = serde_json::from_str(&json)?;
        assert_eq!(decoded, wrapped);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ShortCode additional TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_shortcode_new_empty() {
        let result = ShortCode::new("");
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_new_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new("000000000000")?;
        assert_eq!(code.as_str(), "000000000000");
        Ok(())
    }

    #[test]
    fn test_shortcode_new_all_nines() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new("999999999999")?;
        assert_eq!(code.as_str(), "999999999999");
        Ok(())
    }

    #[test]
    fn test_shortcode_new_with_tabs() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new("1234\t5678\t9012")?;
        assert_eq!(code.as_str(), "123456789012");
        Ok(())
    }

    #[test]
    fn test_shortcode_display_formatted_padding() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new("000000000001")?;
        assert_eq!(code.display_formatted(), "0000 0000 0001");
        Ok(())
    }

    /* ========================================================================== */
    /*                    PkceCodeVerifier additional TESTS                      */
    /* ========================================================================== */

    #[test]
    fn test_pkce_verifier_debug_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let json = format!("\"{}\"", "a".repeat(50));
        let parsed: PkceCodeVerifier = serde_json::from_str(&json)?;
        let debug = format!("{:?}", parsed);
        assert_eq!(debug, "PkceCodeVerifier(***redacted***)");
        assert!(!debug.contains("aaaa"));
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_hyphen_dot_underscore_tilde() -> Result<(), Box<dyn std::error::Error>> {
        // RFC 7636 unreserved chars: A-Z a-z 0-9 - . _ ~
        let verifier = format!("{}{}", "a".repeat(39), "-._~");
        let json = format!("\"{}\"", verifier);
        let parsed: PkceCodeVerifier = serde_json::from_str(&json)?;
        assert_eq!(parsed.as_str(), verifier);
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_space_rejected() {
        let inner = format!("{} {}", "a".repeat(21), "b".repeat(21));
        let json = format!("\"{}\"", inner);
        let result: Result<PkceCodeVerifier, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    PkceMethod additional TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_pkce_method_deserialize_lowercase_rejected() {
        let json = "\"s256\"";
        let result: Result<PkceMethod, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_method_deserialize_unknown_rejected() {
        let json = "\"PLAIN\"";
        let result: Result<PkceMethod, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_method_clone_copy() {
        let m = PkceMethod::S256;
        let m2 = m;
        assert_eq!(m, m2);
    }

    /* ========================================================================== */
    /*                    CutoffDays additional TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_cutoff_days_zero() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff = CutoffDays::new(0)?;
        assert_eq!(cutoff.get(), 0);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_negative() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff = CutoffDays::new(-1000)?;
        assert_eq!(cutoff.get(), -1000);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_clone_copy() -> Result<(), Box<dyn std::error::Error>> {
        let c = CutoffDays::new(100)?;
        let c2 = c;
        assert_eq!(c, c2);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_debug() -> Result<(), Box<dyn std::error::Error>> {
        let c = CutoffDays::new(6570)?;
        let debug = format!("{:?}", c);
        assert!(debug.contains("6570"));
        Ok(())
    }

    #[test]
    fn test_cutoff_days_deserialize_negative() -> Result<(), Box<dyn std::error::Error>> {
        let json = "-5000";
        let cutoff: CutoffDays = serde_json::from_str(json)?;
        assert_eq!(cutoff.get(), -5000);
        Ok(())
    }

    /* ========================================================================== */
    /*                    VkId additional TESTS                                  */
    /* ========================================================================== */

    #[test]
    fn test_vkid_new_max() -> Result<(), Box<dyn std::error::Error>> {
        let vkid = VkId::new(u32::MAX).ok_or("VkId::new(MAX) returned None")?;
        assert_eq!(vkid.get(), u32::MAX);
        Ok(())
    }

    #[test]
    fn test_vkid_new_one() -> Result<(), Box<dyn std::error::Error>> {
        let vkid = VkId::new(1).ok_or("VkId::new(1) returned None")?;
        assert_eq!(vkid.get(), 1);
        Ok(())
    }

    #[test]
    fn test_vkid_clone_copy() -> Result<(), Box<dyn std::error::Error>> {
        let v = VkId::new(5).ok_or("VkId::new(5) returned None")?;
        let v2 = v;
        assert_eq!(v, v2);
        Ok(())
    }

    #[test]
    fn test_vkid_debug() -> Result<(), Box<dyn std::error::Error>> {
        let v = VkId::new(42).ok_or("VkId::new(42) returned None")?;
        let debug = format!("{:?}", v);
        assert!(debug.contains("42"));
        Ok(())
    }

    #[test]
    fn test_vkid_serialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let v = VkId::new(999).ok_or("VkId::new(999) returned None")?;
        let json = serde_json::to_string(&v)?;
        let decoded: VkId = serde_json::from_str(&json)?;
        assert_eq!(v, decoded);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ExpiresIn additional TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_expiresin_min_boundary() {
        let expires = ExpiresIn::new(60);
        assert_eq!(expires.get(), 60);
    }

    #[test]
    fn test_expiresin_max_boundary() {
        let expires = ExpiresIn::new(300);
        assert_eq!(expires.get(), 300);
    }

    #[test]
    fn test_expiresin_just_below_min() {
        let expires = ExpiresIn::new(59);
        assert_eq!(expires.get(), 60);
    }

    #[test]
    fn test_expiresin_just_above_max() {
        let expires = ExpiresIn::new(301);
        assert_eq!(expires.get(), 300);
    }

    #[test]
    fn test_expiresin_u64_max() {
        let expires = ExpiresIn::new(u64::MAX);
        assert_eq!(expires.get(), 300);
    }

    #[test]
    fn test_expiresin_clone_copy() {
        let e = ExpiresIn::new(120);
        let e2 = e;
        assert_eq!(e, e2);
    }

    #[test]
    fn test_expiresin_debug() {
        let e = ExpiresIn::new(180);
        let debug = format!("{:?}", e);
        assert!(debug.contains("180"));
    }

    #[test]
    fn test_expiresin_serialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let e = ExpiresIn::new(200);
        let json = serde_json::to_string(&e)?;
        let decoded: ExpiresIn = serde_json::from_str(&json)?;
        assert_eq!(e, decoded);
        Ok(())
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: B64Url32 roundtrip serialisation
        #[test]
        fn prop_b64url32_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
            let b64 = B64Url32::new(bytes);
            let json = serde_json::to_string(&b64).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let decoded: B64Url32 = serde_json::from_str(&json).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(b64.as_bytes(), decoded.as_bytes());
        }

        /// Property: B64Url192 roundtrip serialisation
        ///
        /// ASVS V6.5.3 ACCEPTED RISK: Uses deterministic seeded RNG for test reproducibility.
        /// This is test-only code (inside #[cfg(test)] module) and deterministic behaviour
        /// is required for property-based tests to be reproducible across runs.
        #[test]
        fn prop_b64url192_roundtrip(seed in any::<u64>()) {
            use rand::{SeedableRng, RngCore};
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let mut bytes = [0u8; 192];
            rng.fill_bytes(&mut bytes);

            let b64 = B64Url192::new(bytes);
            let json = serde_json::to_string(&b64).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let decoded: B64Url192 = serde_json::from_str(&json).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(b64.as_bytes(), decoded.as_bytes());
        }

        /// Property: PKCE verifier length validation
        #[test]
        fn prop_pkce_verifier_length(len in 43usize..=128) {
            let verifier = "a".repeat(len);
            let json = format!("\"{}\"", verifier);
            let result: Result<PkceCodeVerifier, _> = serde_json::from_str(&json);
            prop_assert!(result.is_ok());
        }

        /// Property: PKCE verifier rejects invalid lengths
        #[test]
        fn prop_pkce_verifier_invalid_length(len in 0usize..43) {
            let verifier = "a".repeat(len);
            let json = format!("\"{}\"", verifier);
            let result: Result<PkceCodeVerifier, _> = serde_json::from_str(&json);
            prop_assert!(result.is_err());
        }

        /// Property: CutoffDays within range are valid
        #[test]
        fn prop_cutoff_days_valid_range(days in CutoffDays::MIN..=CutoffDays::MAX) {
            let cutoff = CutoffDays::new(days).map_err(|e| TestCaseError::fail(e))?;
            prop_assert_eq!(cutoff.get(), days);
        }

        /// Property: CutoffDays below MIN are invalid
        #[test]
        fn prop_cutoff_days_below_min(days in (i32::MIN..CutoffDays::MIN)) {
            let result = CutoffDays::new(days);
            prop_assert!(result.is_err());
        }

        /// Property: CutoffDays above MAX are invalid
        #[test]
        fn prop_cutoff_days_above_max(days in (CutoffDays::MAX + 1)..=i32::MAX) {
            let result = CutoffDays::new(days);
            prop_assert!(result.is_err());
        }

        /// Property: VkId non-zero values are valid
        #[test]
        fn prop_vkid_nonzero_valid(id in 1u32..1000) {
            let vkid = VkId::new(id).ok_or_else(|| TestCaseError::fail("VkId::new returned None"))?;
            prop_assert_eq!(vkid.get(), id);
        }

        /// Property: ExpiresIn clamping behaviour
        #[test]
        fn prop_expiresin_clamping(value in any::<u64>()) {
            let expires = ExpiresIn::new(value);
            let result = expires.get();

            prop_assert!(result >= ExpiresIn::MIN);
            prop_assert!(result <= ExpiresIn::MAX);
        }

        /// Property: ExpiresIn values within range preserved
        #[test]
        fn prop_expiresin_preserves_valid(value in ExpiresIn::MIN..=ExpiresIn::MAX) {
            let expires = ExpiresIn::new(value);
            prop_assert_eq!(expires.get(), value);
        }

        /// Property: B64Url32 display is always redacted
        #[test]
        fn prop_b64url32_display_length(bytes in prop::array::uniform32(any::<u8>())) {
            let b64 = B64Url32::new(bytes);
            let s = b64.to_string();
            prop_assert_eq!(s, "[REDACTED]");
        }

        /// Property: B64Url192 display is always redacted
        #[test]
        fn prop_b64url192_display_length(seed in any::<u64>()) {
            use rand::{SeedableRng, RngCore};
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let mut bytes = [0u8; 192];
            rng.fill_bytes(&mut bytes);

            let b64 = B64Url192::new(bytes);
            let s = b64.to_string();
            prop_assert_eq!(s, "[REDACTED]");
        }
    }

    /* ========================================================================== */
    /*                    B64Url32 additional edge cases                         */
    /* ========================================================================== */

    #[test]
    fn test_b64url32_deserialize_empty_string() {
        let json = "\"\"";
        let result: Result<B64Url32, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url32_deserialize_single_char() {
        let json = "\"A\"";
        let result: Result<B64Url32, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url32_deserialize_hyphen_and_underscore_allowed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = [0xFFu8; 32];
        bytes[0] = 0xFB;
        bytes[1] = 0xFF;
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        assert_eq!(encoded.len(), 43);
        let json = format!("\"{}\"", encoded);
        let b64: B64Url32 = serde_json::from_str(&json)?;
        assert_eq!(*b64.as_bytes(), bytes);
        Ok(())
    }

    #[test]
    fn test_b64url32_hash_set_dedup() {
        use std::collections::HashSet;
        let b1 = B64Url32::new([1u8; 32]);
        let b2 = B64Url32::new([2u8; 32]);
        let b3 = B64Url32::new([1u8; 32]);
        let mut set = HashSet::new();
        set.insert(b1);
        set.insert(b2);
        set.insert(b3);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_b64url32_serialize_length() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = [0u8; 32];
        let b64 = B64Url32::new(bytes);
        let json = serde_json::to_string(&b64)?;
        assert_eq!(json.len(), 45); // 43 base64url chars + 2 quotes
        Ok(())
    }

    #[test]
    fn test_b64url32_roundtrip_sequential() -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let b64 = B64Url32::new(bytes);
        let json = serde_json::to_string(&b64)?;
        let decoded: B64Url32 = serde_json::from_str(&json)?;
        assert_eq!(decoded.as_bytes(), &bytes);
        Ok(())
    }

    #[test]
    fn test_b64url32_deserialize_whitespace_rejected() {
        let json = "\" AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"";
        let result: Result<B64Url32, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url32_deserialize_newline_rejected() {
        let json = "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\n\"";
        let result: Result<B64Url32, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    B64Url192 additional edge cases                        */
    /* ========================================================================== */

    #[test]
    fn test_b64url192_deserialize_empty_string() {
        let json = "\"\"";
        let result: Result<B64Url192, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url192_deserialize_single_char() {
        let json = "\"A\"";
        let result: Result<B64Url192, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url192_deserialize_slash_rejected() {
        let json = format!("\"{}/\"", "A".repeat(255));
        let result: Result<B64Url192, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url192_deserialize_padding_rejected() {
        let json = format!("\"{}=\"", "A".repeat(255));
        let result: Result<B64Url192, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url192_roundtrip_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let b64 = B64Url192::new([0u8; 192]);
        let json = serde_json::to_string(&b64)?;
        let decoded: B64Url192 = serde_json::from_str(&json)?;
        assert_eq!(decoded.as_bytes(), &[0u8; 192]);
        Ok(())
    }

    #[test]
    fn test_b64url192_roundtrip_all_ff() -> Result<(), Box<dyn std::error::Error>> {
        let b64 = B64Url192::new([0xFFu8; 192]);
        let json = serde_json::to_string(&b64)?;
        let decoded: B64Url192 = serde_json::from_str(&json)?;
        assert_eq!(decoded.as_bytes(), &[0xFFu8; 192]);
        Ok(())
    }

    #[test]
    fn test_b64url192_serialize_length() -> Result<(), Box<dyn std::error::Error>> {
        let b64 = B64Url192::new([0u8; 192]);
        let json = serde_json::to_string(&b64)?;
        assert_eq!(json.len(), 258); // 256 base64url chars + 2 quotes
        Ok(())
    }

    #[test]
    fn test_b64url192_hash_set_dedup() {
        use std::collections::HashSet;
        let b1 = B64Url192::new([1u8; 192]);
        let b2 = B64Url192::new([2u8; 192]);
        let b3 = B64Url192::new([1u8; 192]);
        let mut set = HashSet::new();
        set.insert(b1);
        set.insert(b2);
        set.insert(b3);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_b64url192_display_nonzero() {
        let b64 = B64Url192::new([0xABu8; 192]);
        assert_eq!(b64.to_string(), "[REDACTED]");
    }

    #[test]
    fn test_b64url192_roundtrip_sequential() -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = [0u8; 192];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let b64 = B64Url192::new(bytes);
        let json = serde_json::to_string(&b64)?;
        let decoded: B64Url192 = serde_json::from_str(&json)?;
        assert_eq!(decoded.as_bytes(), &bytes);
        Ok(())
    }

    #[test]
    fn test_b64url192_deserialize_whitespace_rejected() {
        let json = format!("\" {}\"", "A".repeat(255));
        let result: Result<B64Url192, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64url192_deserialize_exactly_255() {
        let json = format!("\"{}\"", "A".repeat(255));
        let result: Result<B64Url192, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    UuidV4 additional edge cases                           */
    /* ========================================================================== */

    #[test]
    fn test_uuidv4_deserialize_v3_rejected() {
        let json = "\"a3bb189e-8bf9-3888-9912-ace4e6543002\"";
        let result: Result<UuidV4, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_uuidv4_deserialize_v5_rejected() {
        let json = "\"74738ff5-5367-5958-9aee-98fffdcd1876\"";
        let result: Result<UuidV4, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_uuidv4_deserialize_empty_rejected() {
        let json = "\"\"";
        let result: Result<UuidV4, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_uuidv4_deserialize_too_long_rejected() {
        let json = "\"550e8400-e29b-41d4-a716-4466554400001\"";
        let result: Result<UuidV4, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_uuidv4_debug_contains_variant_name() {
        let uuid = Uuid::new_v4();
        let wrapped = UuidV4(uuid);
        let debug = format!("{:?}", wrapped);
        assert!(debug.contains("UuidV4"));
    }

    #[test]
    fn test_uuidv4_eq_reflexive() {
        let u = UuidV4(Uuid::new_v4());
        assert_eq!(u, u);
    }

    /* ========================================================================== */
    /*                    ShortCode additional edge cases                        */
    /* ========================================================================== */

    #[test]
    fn test_shortcode_new_letters_rejected() {
        let result = ShortCode::new("abcdef123456");
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_new_special_chars_rejected() {
        let result = ShortCode::new("123456789-12");
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_new_leading_spaces() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new(" 123456789012")?;
        assert_eq!(code.as_str(), "123456789012");
        Ok(())
    }

    #[test]
    fn test_shortcode_new_trailing_spaces() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new("123456789012 ")?;
        assert_eq!(code.as_str(), "123456789012");
        Ok(())
    }

    #[test]
    fn test_shortcode_new_only_spaces() {
        let result = ShortCode::new("            ");
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_deserialize_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let json = "\"000000000000\"";
        let code: ShortCode = serde_json::from_str(json)?;
        assert_eq!(code.as_str(), "000000000000");
        Ok(())
    }

    #[test]
    fn test_shortcode_deserialize_all_nines() -> Result<(), Box<dyn std::error::Error>> {
        let json = "\"999999999999\"";
        let code: ShortCode = serde_json::from_str(json)?;
        assert_eq!(code.as_str(), "999999999999");
        Ok(())
    }

    #[test]
    fn test_shortcode_deserialize_letters_rejected() {
        let json = "\"12345678901a\"";
        let result: Result<ShortCode, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_serialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new("111222333444")?;
        let json = serde_json::to_string(&code)?;
        let decoded: ShortCode = serde_json::from_str(&json)?;
        assert_eq!(decoded.as_str(), "111222333444");
        Ok(())
    }

    #[test]
    fn test_shortcode_display_formatted_all_same() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new("111111111111")?;
        assert_eq!(code.display_formatted(), "1111 1111 1111");
        Ok(())
    }

    #[test]
    fn test_shortcode_new_error_message_contains_length() {
        let err = ShortCode::new("123").err();
        assert!(err.is_some());
        let msg = err.expect("expected error");
        assert!(msg.contains("12 digits"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn test_shortcode_new_non_digit_error_message() {
        let err = ShortCode::new("abcdefghijkl").err();
        assert!(err.is_some());
        let msg = err.expect("expected error");
        assert!(msg.contains("numeric digits"));
    }

    #[test]
    fn test_shortcode_deserialize_with_newlines_as_whitespace(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = "\"1234\\n56789012\"";
        let code: ShortCode = serde_json::from_str(json)?;
        assert_eq!(code.as_str(), "123456789012");
        Ok(())
    }

    /* ========================================================================== */
    /*                    PkceCodeVerifier additional edge cases                 */
    /* ========================================================================== */

    #[test]
    fn test_pkce_verifier_deserialize_empty_rejected() {
        let json = "\"\"";
        let result: Result<PkceCodeVerifier, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_verifier_deserialize_numeric_only() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = "1".repeat(43);
        let json = format!("\"{}\"", verifier);
        let result: PkceCodeVerifier = serde_json::from_str(&json)?;
        assert_eq!(result.as_str(), verifier);
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_deserialize_uppercase_only() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = "A".repeat(128);
        let json = format!("\"{}\"", verifier);
        let result: PkceCodeVerifier = serde_json::from_str(&json)?;
        assert_eq!(result.as_str(), verifier);
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_deserialize_mixed_unreserved() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = format!("{}aB1-._~aB1-._~aB1-._~aB1-._~aB1-._~aB1", "Z".repeat(5));
        assert!(verifier.len() >= 43);
        let json = format!("\"{}\"", verifier);
        let result: PkceCodeVerifier = serde_json::from_str(&json)?;
        assert_eq!(result.as_str(), verifier);
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_deserialize_at_sign_rejected() {
        let json = format!("\"{}@\"", "a".repeat(42));
        let result: Result<PkceCodeVerifier, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_verifier_deserialize_hash_rejected() {
        let json = format!("\"{}#\"", "a".repeat(42));
        let result: Result<PkceCodeVerifier, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_verifier_deserialize_slash_rejected() {
        let json = format!("\"{}/\"", "a".repeat(42));
        let result: Result<PkceCodeVerifier, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_verifier_serialize_roundtrip_full() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = "b".repeat(64);
        let json_in = format!("\"{}\"", verifier);
        let parsed: PkceCodeVerifier = serde_json::from_str(&json_in)?;
        let json_out = serde_json::to_string(&parsed)?;
        let reparsed: PkceCodeVerifier = serde_json::from_str(&json_out)?;
        assert_eq!(reparsed.as_str(), verifier);
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_clone_eq() -> Result<(), Box<dyn std::error::Error>> {
        let json = format!("\"{}\"", "c".repeat(50));
        let a: PkceCodeVerifier = serde_json::from_str(&json)?;
        let b = a.clone();
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_hash_set_dedup() -> Result<(), Box<dyn std::error::Error>> {
        use std::collections::HashSet;
        let json1 = format!("\"{}\"", "a".repeat(43));
        let json2 = format!("\"{}\"", "b".repeat(43));
        let p1: PkceCodeVerifier = serde_json::from_str(&json1)?;
        let p2: PkceCodeVerifier = serde_json::from_str(&json2)?;
        let p3: PkceCodeVerifier = serde_json::from_str(&json1)?;
        let mut set = HashSet::new();
        set.insert(p1);
        set.insert(p2);
        set.insert(p3);
        assert_eq!(set.len(), 2);
        Ok(())
    }

    /* ========================================================================== */
    /*                    PkceMethod additional edge cases                       */
    /* ========================================================================== */

    #[test]
    fn test_pkce_method_serialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let m = PkceMethod::S256;
        let json = serde_json::to_string(&m)?;
        let decoded: PkceMethod = serde_json::from_str(&json)?;
        assert_eq!(decoded, PkceMethod::S256);
        Ok(())
    }

    #[test]
    fn test_pkce_method_debug_contains_s256() {
        let debug = format!("{:?}", PkceMethod::S256);
        assert!(debug.contains("S256"));
    }

    #[test]
    fn test_pkce_method_deserialize_empty_rejected() {
        let json = "\"\"";
        let result: Result<PkceMethod, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_method_deserialize_sha256_rejected() {
        let json = "\"SHA256\"";
        let result: Result<PkceMethod, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    CutoffDays additional edge cases                       */
    /* ========================================================================== */

    #[test]
    fn test_cutoff_days_new_exactly_min_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff = CutoffDays::new(CutoffDays::MIN)?;
        assert_eq!(cutoff.get(), CutoffDays::MIN);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_exactly_max_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff = CutoffDays::new(CutoffDays::MAX)?;
        assert_eq!(cutoff.get(), CutoffDays::MAX);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_one() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff = CutoffDays::new(1)?;
        assert_eq!(cutoff.get(), 1);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_negative_one() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff = CutoffDays::new(-1)?;
        assert_eq!(cutoff.get(), -1);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_far_below_min() {
        let result = CutoffDays::new(i32::MIN);
        assert!(result.is_err());
    }

    #[test]
    fn test_cutoff_days_new_far_above_max() {
        let result = CutoffDays::new(i32::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn test_cutoff_days_error_message_format() {
        let err = CutoffDays::new(100_000).err();
        assert!(err.is_some());
        let msg = err.expect("expected error");
        assert!(msg.contains("100000"));
        assert!(msg.contains("out of range"));
    }

    #[test]
    fn test_cutoff_days_deserialize_zero() -> Result<(), Box<dyn std::error::Error>> {
        let json = "0";
        let cutoff: CutoffDays = serde_json::from_str(json)?;
        assert_eq!(cutoff.get(), 0);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_deserialize_min_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let json = format!("{}", CutoffDays::MIN);
        let cutoff: CutoffDays = serde_json::from_str(&json)?;
        assert_eq!(cutoff.get(), CutoffDays::MIN);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_deserialize_max_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let json = format!("{}", CutoffDays::MAX);
        let cutoff: CutoffDays = serde_json::from_str(&json)?;
        assert_eq!(cutoff.get(), CutoffDays::MAX);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_deserialize_below_min_rejected() {
        let json = format!("{}", CutoffDays::MIN - 1);
        let result: Result<CutoffDays, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_cutoff_days_deserialize_above_max_rejected() {
        let json = format!("{}", CutoffDays::MAX + 1);
        let result: Result<CutoffDays, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_cutoff_days_serialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let c = CutoffDays::new(365)?;
        let json = serde_json::to_string(&c)?;
        let decoded: CutoffDays = serde_json::from_str(&json)?;
        assert_eq!(decoded.get(), 365);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_serialize_negative_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let c = CutoffDays::new(-500)?;
        let json = serde_json::to_string(&c)?;
        let decoded: CutoffDays = serde_json::from_str(&json)?;
        assert_eq!(decoded.get(), -500);
        Ok(())
    }

    /* ========================================================================== */
    /*                    VkId additional edge cases                             */
    /* ========================================================================== */

    #[test]
    fn test_vkid_new_two() -> Result<(), Box<dyn std::error::Error>> {
        let vkid = VkId::new(2).ok_or("VkId::new(2) returned None")?;
        assert_eq!(vkid.get(), 2);
        Ok(())
    }

    #[test]
    fn test_vkid_deserialize_one() -> Result<(), Box<dyn std::error::Error>> {
        let json = "1";
        let vkid: VkId = serde_json::from_str(json)?;
        assert_eq!(vkid.get(), 1);
        Ok(())
    }

    #[test]
    fn test_vkid_deserialize_max() -> Result<(), Box<dyn std::error::Error>> {
        let json = format!("{}", u32::MAX);
        let vkid: VkId = serde_json::from_str(&json)?;
        assert_eq!(vkid.get(), u32::MAX);
        Ok(())
    }

    #[test]
    fn test_vkid_deserialize_negative_rejected() {
        let json = "-1";
        let result: Result<VkId, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_vkid_deserialize_float_rejected() {
        let json = "1.5";
        let result: Result<VkId, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_vkid_deserialize_string_rejected() {
        let json = "\"42\"";
        let result: Result<VkId, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_vkid_eq_reflexive() -> Result<(), Box<dyn std::error::Error>> {
        let v = VkId::new(10).ok_or("VkId::new(10) returned None")?;
        assert_eq!(v, v);
        Ok(())
    }

    #[test]
    fn test_vkid_ne() -> Result<(), Box<dyn std::error::Error>> {
        let v1 = VkId::new(1).ok_or("VkId::new(1) returned None")?;
        let v2 = VkId::new(2).ok_or("VkId::new(2) returned None")?;
        assert_ne!(v1, v2);
        Ok(())
    }

    #[test]
    fn test_vkid_equality_dedup() -> Result<(), Box<dyn std::error::Error>> {
        let v1 = VkId::new(1).ok_or("failed")?;
        let v2 = VkId::new(2).ok_or("failed")?;
        let v3 = VkId::new(1).ok_or("failed")?;
        let items = vec![v1, v2, v3];
        let mut deduped: Vec<VkId> = Vec::new();
        for item in items {
            if !deduped.contains(&item) {
                deduped.push(item);
            }
        }
        assert_eq!(deduped.len(), 2);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ExpiresIn additional edge cases                        */
    /* ========================================================================== */

    #[test]
    fn test_expiresin_new_exact_min_value() {
        let e = ExpiresIn::new(ExpiresIn::MIN);
        assert_eq!(e.get(), ExpiresIn::MIN);
    }

    #[test]
    fn test_expiresin_new_exact_max_value() {
        let e = ExpiresIn::new(ExpiresIn::MAX);
        assert_eq!(e.get(), ExpiresIn::MAX);
    }

    #[test]
    fn test_expiresin_new_midpoint() {
        let mid = (ExpiresIn::MIN + ExpiresIn::MAX) / 2;
        let e = ExpiresIn::new(mid);
        assert_eq!(e.get(), mid);
    }

    #[test]
    fn test_expiresin_new_one_clamped() {
        let e = ExpiresIn::new(1);
        assert_eq!(e.get(), ExpiresIn::MIN);
    }

    #[test]
    fn test_expiresin_deserialize_exact_min() -> Result<(), Box<dyn std::error::Error>> {
        let json = format!("{}", ExpiresIn::MIN);
        let e: ExpiresIn = serde_json::from_str(&json)?;
        assert_eq!(e.get(), ExpiresIn::MIN);
        Ok(())
    }

    #[test]
    fn test_expiresin_deserialize_exact_max() -> Result<(), Box<dyn std::error::Error>> {
        let json = format!("{}", ExpiresIn::MAX);
        let e: ExpiresIn = serde_json::from_str(&json)?;
        assert_eq!(e.get(), ExpiresIn::MAX);
        Ok(())
    }

    #[test]
    fn test_expiresin_deserialize_zero_clamped_to_min() -> Result<(), Box<dyn std::error::Error>> {
        let json = "0";
        let e: ExpiresIn = serde_json::from_str(json)?;
        assert_eq!(e.get(), ExpiresIn::MIN);
        Ok(())
    }

    #[test]
    fn test_expiresin_deserialize_negative_rejected() {
        let json = "-1";
        let result: Result<ExpiresIn, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_expiresin_deserialize_float_rejected() {
        let json = "60.5";
        let result: Result<ExpiresIn, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_expiresin_deserialize_string_rejected() {
        let json = "\"60\"";
        let result: Result<ExpiresIn, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_expiresin_eq() {
        let a = ExpiresIn::new(120);
        let b = ExpiresIn::new(120);
        assert_eq!(a, b);
    }

    #[test]
    fn test_expiresin_ne() {
        let a = ExpiresIn::new(60);
        let b = ExpiresIn::new(300);
        assert_ne!(a, b);
    }

    #[test]
    fn test_expiresin_default_eq_new_300() {
        assert_eq!(ExpiresIn::default(), ExpiresIn::new(300));
    }

    /* ========================================================================== */
    /*                    B64Url32 ne                                            */
    /* ========================================================================== */

    #[test]
    fn test_b64url32_ne() {
        let a = B64Url32::new([0u8; 32]);
        let b = B64Url32::new([1u8; 32]);
        assert_ne!(a, b);
    }

    /* ========================================================================== */
    /*                    B64Url192 ne                                           */
    /* ========================================================================== */

    #[test]
    fn test_b64url192_ne() {
        let a = B64Url192::new([0u8; 192]);
        let b = B64Url192::new([1u8; 192]);
        assert_ne!(a, b);
    }

    /* ========================================================================== */
    /*                    CutoffDays constants                                   */
    /* ========================================================================== */

    #[test]
    fn test_cutoff_days_min_is_negative() {
        assert!(CutoffDays::MIN < 0);
    }

    #[test]
    fn test_cutoff_days_max_is_positive() {
        assert!(CutoffDays::MAX > 0);
    }

    #[test]
    fn test_cutoff_days_min_less_than_max() {
        assert!(CutoffDays::MIN < CutoffDays::MAX);
    }

    /* ========================================================================== */
    /*                    ExpiresIn constants                                    */
    /* ========================================================================== */

    #[test]
    fn test_expiresin_min_is_60() {
        assert_eq!(ExpiresIn::MIN, 60);
    }

    #[test]
    fn test_expiresin_max_is_300() {
        assert_eq!(ExpiresIn::MAX, 300);
    }

    #[test]
    fn test_expiresin_min_less_than_max() {
        assert!(ExpiresIn::MIN < ExpiresIn::MAX);
    }

    /* ========================================================================== */
    /*                    ShortCode Debug                                        */
    /* ========================================================================== */

    #[test]
    fn test_shortcode_debug_format() -> Result<(), Box<dyn std::error::Error>> {
        let code = ShortCode::new("123456789012")?;
        let debug = format!("{:?}", code);
        assert!(debug.contains("ShortCode"));
        assert!(debug.contains("123456789012"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    CutoffDays Serialise format                            */
    /* ========================================================================== */

    #[test]
    fn test_cutoff_days_serialize_zero() -> Result<(), Box<dyn std::error::Error>> {
        let c = CutoffDays::new(0)?;
        let json = serde_json::to_string(&c)?;
        assert_eq!(json, "0");
        Ok(())
    }

    #[test]
    fn test_cutoff_days_serialize_negative() -> Result<(), Box<dyn std::error::Error>> {
        let c = CutoffDays::new(-100)?;
        let json = serde_json::to_string(&c)?;
        assert_eq!(json, "-100");
        Ok(())
    }

    #[test]
    fn test_cutoff_days_serialize_min() -> Result<(), Box<dyn std::error::Error>> {
        let c = CutoffDays::new(CutoffDays::MIN)?;
        let json = serde_json::to_string(&c)?;
        assert_eq!(json, format!("{}", CutoffDays::MIN));
        Ok(())
    }

    #[test]
    fn test_cutoff_days_serialize_max() -> Result<(), Box<dyn std::error::Error>> {
        let c = CutoffDays::new(CutoffDays::MAX)?;
        let json = serde_json::to_string(&c)?;
        assert_eq!(json, format!("{}", CutoffDays::MAX));
        Ok(())
    }

    /* ========================================================================== */
    /*                    VkId Serialise format                                  */
    /* ========================================================================== */

    #[test]
    fn test_vkid_serialize_one() -> Result<(), Box<dyn std::error::Error>> {
        let v = VkId::new(1).ok_or("failed")?;
        let json = serde_json::to_string(&v)?;
        assert_eq!(json, "1");
        Ok(())
    }

    #[test]
    fn test_vkid_serialize_max() -> Result<(), Box<dyn std::error::Error>> {
        let v = VkId::new(u32::MAX).ok_or("failed")?;
        let json = serde_json::to_string(&v)?;
        assert_eq!(json, format!("{}", u32::MAX));
        Ok(())
    }
}
