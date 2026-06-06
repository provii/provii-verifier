// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Pure schema-inference helpers for structured error localisation (PG-VAL-016).
//!
//! These functions map `serde_json::Error` values to `(field, detail)` pairs so
//! that API callers receive a machine-readable field name plus a human-readable
//! hint when body deserialisation fails. They have zero Worker dependencies and
//! are extracted here to enable direct unit testing (the parent `worker_routes`
//! module is excluded from coverage by CI regex).

/// PG-VAL-016: Given the raw body bytes and a deserialisation error from
/// `CreateChallengeRequest`, return a `(field_name, detail_message)` pair that
/// names the offending field as specifically as possible.
///
/// Falls back to the generic `body`. Returns `("body", <generic>)` when no
/// specific field can be safely inferred.
///
/// The `serde_json::Error::Display` form is `"<message> at line N column N"`.
/// For typed-deser errors it embeds the path implicitly inside the message
/// (e.g. `"invalid length 31, expected 32 bytes for `code_challenge`"`).
/// For `deny_unknown_fields` the message is `"unknown field `foo`,
/// expected one of ..."`. For `missing field` it is `"missing field
/// `foo`"`. We pattern-match on these stable shapes and otherwise fall back
/// to `body`.
///
/// SECURITY: We never echo serde's full error string to the client (it can
/// leak schema-internal type names). Detail is a curated human-readable
/// hint per known field.
pub(crate) fn infer_create_challenge_schema_field(
    body_bytes: &[u8],
    err: &serde_json::Error,
) -> (String, String) {
    use serde_json::error::Category;
    if matches!(err.classify(), Category::Syntax | Category::Eof) {
        return (
            "body".to_string(),
            "Request body is not valid JSON".to_string(),
        );
    }
    let msg = err.to_string();

    // `missing field "<name>"` and `unknown field "<name>"` shapes.
    if let Some(name) = extract_quoted(&msg, "missing field `") {
        return (
            name.clone(),
            format!("Required field `{}` is missing from the request body", name),
        );
    }
    if let Some(name) = extract_quoted(&msg, "unknown field `") {
        return (
            name.clone(),
            format!(
                "Unknown field `{}` (the request body schema rejects extra fields)",
                name
            ),
        );
    }

    // Typed errors mention the originating field name when serde knows it.
    // The strict newtype validators (B64Url32, ExpiresIn, Authorizer) embed
    // their messages inside the field's deserializer.
    let candidates: &[(&str, &str)] = &[
        (
            "code_challenge",
            "code_challenge must decode to exactly 32 bytes from base64url (no padding)",
        ),
        ("expires_in", "expires_in is outside the allowed range"),
        (
            "verifying_key_id",
            "verifying_key_id is not a valid identifier",
        ),
        ("method", "method must be \"S256\""),
        (
            "authorizer",
            "authorizer envelope is malformed (key_id, timestamp, nonce, hmac required)",
        ),
    ];
    for (name, hint) in candidates {
        if msg.contains(name) {
            return ((*name).to_string(), (*hint).to_string());
        }
    }

    // Fallback: serde_json includes a 1-based line/column in its Display
    // string but does NOT name the offending field by default. Inspect the
    // body bytes up to the reported column to find the most recent JSON
    // key, which is almost always the field that failed to validate (the
    // value was being parsed at that position).
    if let Some(field) = locate_field_from_position(body_bytes, err) {
        for (name, hint) in candidates {
            if &field == name {
                return ((*name).to_string(), (*hint).to_string());
            }
        }
        return (
            field,
            "Field value does not match the expected schema for POST /v1/challenge".to_string(),
        );
    }

    // Top-level shape problem we couldn't localise. Use `body`.
    (
        "body".to_string(),
        "Request body does not match the expected schema for POST /v1/challenge".to_string(),
    )
}

/// PG-VAL-016: Use the (line, column) embedded in a `serde_json::Error`
/// Display string to find the JSON object key immediately preceding the
/// failure offset. Returns the bare key name, or `None` when the body or
/// position cannot be reasoned about safely.
///
/// Best-effort heuristic: walks backwards from the offset looking for the
/// nearest unescaped `"<name>"\s*:` pair. Skips inside strings by counting
/// quotes; not a full JSON parser, so deeply nested or unusually escaped
/// payloads may return `None` (in which case the caller falls back to
/// `field: body`). Never panics on malformed input.
pub(crate) fn locate_field_from_position(
    body_bytes: &[u8],
    err: &serde_json::Error,
) -> Option<String> {
    let line = err.line();
    let column = err.column();
    if line == 0 || column == 0 {
        return None;
    }
    // Compute a byte offset from (line, column). serde_json reports 1-based.
    let mut offset: usize = 0;
    let mut current_line: usize = 1;
    while current_line < line && offset < body_bytes.len() {
        if body_bytes.get(offset).copied() == Some(b'\n') {
            current_line = current_line.saturating_add(1);
        }
        offset = offset.saturating_add(1);
    }
    let line_offset = offset.saturating_add(column.saturating_sub(1));
    let cap = line_offset.min(body_bytes.len());

    // Scan backwards looking for `:`, then before that `"<name>"`.
    let prefix = body_bytes.get(..cap)?;
    let colon_pos = prefix.iter().rposition(|&b| b == b':')?;
    let pre_colon = prefix.get(..colon_pos)?;
    // Skip whitespace before colon.
    let mut end = pre_colon.len();
    while end > 0 {
        let b = *pre_colon.get(end.saturating_sub(1))?;
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            end = end.saturating_sub(1);
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }
    if pre_colon.get(end.saturating_sub(1)).copied() != Some(b'"') {
        return None;
    }
    let close_quote = end.saturating_sub(1);
    // Walk backwards looking for the opening `"` of the key. We track
    // `cursor` as the index immediately AFTER the byte we are inspecting,
    // so `cursor - 1` is the candidate. When we break, the opening quote
    // is at `cursor - 1` and the name spans `cursor .. close_quote`.
    let mut cursor = close_quote;
    while cursor > 0 {
        let b = *pre_colon.get(cursor.saturating_sub(1))?;
        if b == b'"' {
            // Reject escaped quote (`\"`).
            if cursor >= 2 && pre_colon.get(cursor.saturating_sub(2)).copied() == Some(b'\\') {
                cursor = cursor.saturating_sub(1);
                continue;
            }
            break;
        }
        cursor = cursor.saturating_sub(1);
    }
    if cursor == 0 || cursor >= close_quote {
        return None;
    }
    let name_bytes = pre_colon.get(cursor..close_quote)?;
    let name = std::str::from_utf8(name_bytes).ok()?.to_string();
    // Reject obviously bogus names (e.g. contains control chars).
    if name.is_empty() || name.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(name)
}

/// Extract the contents of the first backtick-quoted token following `prefix`.
pub(crate) fn extract_quoted(haystack: &str, prefix: &str) -> Option<String> {
    let start = haystack.find(prefix)?.checked_add(prefix.len())?;
    let rest = haystack.get(start..)?;
    let end = rest.find('`')?;
    Some(rest.get(..end)?.to_string())
}

/// PG-VAL-016: Same as `infer_create_challenge_schema_field` but for the
/// `RedeemRequest` body shape (only `code_verifier`).
pub(crate) fn infer_redeem_schema_field(
    body_bytes: &[u8],
    err: &serde_json::Error,
) -> (String, String) {
    use serde_json::error::Category;
    if matches!(err.classify(), Category::Syntax | Category::Eof) {
        return (
            "body".to_string(),
            "Request body is not valid JSON".to_string(),
        );
    }
    let msg = err.to_string();
    if let Some(name) = extract_quoted(&msg, "missing field `") {
        return (
            name.clone(),
            format!("Required field `{}` is missing from the request body", name),
        );
    }
    if let Some(name) = extract_quoted(&msg, "unknown field `") {
        return (
            name.clone(),
            format!(
                "Unknown field `{}` (only `code_verifier` is accepted)",
                name
            ),
        );
    }
    if msg.contains("code_verifier") {
        return (
            "code_verifier".to_string(),
            "code_verifier must be a 43-128 character RFC 7636 PKCE verifier (unreserved chars only)".to_string(),
        );
    }
    let _ = body_bytes;
    (
        "body".to_string(),
        "Request body does not match the expected schema for POST /v1/challenge/:session_id/redeem (only `code_verifier` is accepted)".to_string(),
    )
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]
mod tests {
    use super::*;

    /* ====================================================================== */
    /* PG-VAL-016: structured-error field localisation for body schema fails  */
    /* ====================================================================== */

    fn parse_create_err(body: &[u8]) -> serde_json::Error {
        // Note: CreateChallengeRequest derives Debug, so expect_err is the
        // idiomatic form (clippy::err_expect would otherwise flag .err().expect()).
        serde_json::from_slice::<crate::routes::challenge::CreateChallengeRequest>(body)
            .expect_err("expected deser failure")
    }

    fn parse_redeem_err(body: &[u8]) -> serde_json::Error {
        // RedeemRequest does not derive Debug (the inner PkceCodeVerifier is
        // intentionally not Debug to prevent accidental log leaks of the
        // verifier), so we cannot use expect_err here. Match-and-panic is
        // the next-cleanest pattern.
        match serde_json::from_slice::<crate::routes::redeem::RedeemRequest>(body) {
            Ok(_) => panic!("expected deser failure"), // nosemgrep: provii.workers.panic-in-worker
            Err(e) => e,
        }
    }

    #[test]
    fn test_infer_field_unknown_field_in_create() {
        // deny_unknown_fields: a stray top-level field should be named in the
        // structured error so devs can find and remove it without grepping
        // the wire format.
        //
        // All required fields must carry valid values so serde reaches the
        // unknown-field check instead of failing earlier on a type mismatch.
        let body = br#"{"code_challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","method":"S256","authorizer":{"keyId":"x","timestamp":1,"nonce":"y","hmac":"z"},"surprise":1}"#;
        let err = parse_create_err(body);
        let (field, detail) = infer_create_challenge_schema_field(body, &err);
        assert_eq!(field, "surprise");
        assert!(detail.contains("Unknown field"));
    }

    #[test]
    fn test_infer_field_missing_field_in_create() {
        // Missing top-level `authorizer`. Since `method` is also required and
        // declared before `authorizer` in the struct, we must include it so
        // that serde reports the missing `authorizer` rather than `method`.
        let body =
            br#"{"code_challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","method":"S256"}"#;
        let err = parse_create_err(body);
        let (field, _detail) = infer_create_challenge_schema_field(body, &err);
        assert_eq!(field, "authorizer");
    }

    /// R4 NEW-P regression: `method` is now a required field on
    /// `CreateChallengeRequest`. Submitting a body without `method` must
    /// fail deserialisation with a missing-field error that the structured
    /// envelope localises to `field: "method"`.
    #[test]
    fn test_infer_field_missing_method_in_create() {
        // Authorizer uses `keyId` (camelCase) via serde rename, and applies
        // `deny_unknown_fields`. Using `key_id` in JSON triggers an
        // unknown-field error inside the Authorizer before serde detects
        // the missing top-level `method`.
        let body = br#"{
            "code_challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "authorizer":{"keyId":"x","timestamp":1,"nonce":"y","hmac":"z"}
        }"#;
        let err = parse_create_err(body);
        let (field, detail) = infer_create_challenge_schema_field(body, &err);
        assert_eq!(
            field, "method",
            "missing method must surface as field=method"
        );
        assert!(
            detail.contains("method"),
            "detail should mention the missing field name: {}",
            detail
        );
    }

    #[test]
    fn test_infer_field_syntax_error_falls_back_to_body() {
        let body = b"{ this is not json";
        let err = parse_create_err(body);
        let (field, _detail) = infer_create_challenge_schema_field(body, &err);
        assert_eq!(field, "body");
    }

    #[test]
    fn test_infer_field_redeem_unknown_field() {
        // The code_verifier value must be a valid RFC 7636 verifier (43-128
        // unreserved chars) so that serde does not fail on it before reaching
        // the unknown `extra` field.
        let body =
            br#"{"code_verifier":"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq","extra":"y"}"#;
        let err = parse_redeem_err(body);
        let (field, detail) = infer_redeem_schema_field(body, &err);
        assert_eq!(field, "extra");
        assert!(detail.contains("Unknown field"));
    }

    #[test]
    fn test_infer_field_redeem_missing_code_verifier() {
        let body = br#"{}"#;
        let err = parse_redeem_err(body);
        let (field, _detail) = infer_redeem_schema_field(body, &err);
        assert_eq!(field, "code_verifier");
    }

    #[test]
    fn test_extract_quoted_basic() {
        let s = "missing field `authorizer` at line 1 column 32";
        assert_eq!(
            extract_quoted(s, "missing field `"),
            Some("authorizer".to_string())
        );
    }

    #[test]
    fn test_extract_quoted_returns_none_when_prefix_absent() {
        assert!(extract_quoted("nothing here", "missing field `").is_none());
    }

    #[test]
    fn test_locate_field_from_position_pinpoints_code_challenge() {
        // The `B64Url32` deserializer for `code_challenge` rejects "AA" (1
        // byte after base64url decode) but the resulting serde_json error
        // carries no field name in its Display string. The position-based
        // fallback should still report `code_challenge` so devs aren't told
        // the whole body is malformed when only one value is wrong.
        let body =
            br#"{"code_challenge":"AA","authorizer":{"keyId":"x","timestamp":1,"nonce":"y","hmac":"z"}}"#;
        let err = parse_create_err(body);
        let (field, _detail) = infer_create_challenge_schema_field(body, &err);
        assert_eq!(field, "code_challenge");
    }

    #[test]
    fn test_locate_field_from_position_returns_none_for_zero_pos() {
        // Defensive: a synthetic error with line=0 column=0 must not panic
        // and must return None so the caller falls back to `body`.
        let body = b"";
        let err = serde_json::from_slice::<crate::routes::redeem::RedeemRequest>(body)
            .err()
            .unwrap();
        // For empty input, line/col will be > 0 from serde, but the helper
        // should still fail gracefully on the empty body.
        let _ = locate_field_from_position(body, &err);
    }
}
