// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! `ban-entry-decode` library. Cross-language BanEntry JSON shape contract.
//!
//! Paired with the provii-management Vitest at
//! `provii-management/tests/rotation/banentry-schema.test.ts`. That test captures
//! the JSON `addToBanlist` writes to KV, hands it to the binary as a file
//! path, and asserts a clean exit.
//!
//! ## Why a separate file-local struct
//!
//! `BanEntry` in `src/storage/ban_store.rs` is private and the lib targets
//! wasm32 with worker deps that are not native-buildable. Re-declaring the
//! shape here keeps the bin a leaf target with only `serde` + `serde_json`
//! in its dep graph; the lib is not compiled when this bin is built. The
//! same-shape Rust `serde` test in `ban_store.rs::tests` covers structural
//! drift between the two declarations.

#![forbid(unsafe_code)]

use serde::Deserialize;
use std::io::Read;

/// Mirror of `provii-verifier/src/storage/ban_store.rs::BanEntry`. Keep the four
/// fields, types, and `serde` attributes in lock-step with that struct.
#[derive(Deserialize)]
pub struct BanEntry {
    pub reason: String,
    pub banned_at: i64,
    #[serde(default)]
    pub expires_at: Option<i64>,
    pub banned_by: String,
}

/// Read the contents of a file at `path`.
pub fn read_from_path(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

/// Read input from a file path argument or stdin.
pub fn read_input() -> std::io::Result<String> {
    let mut args = std::env::args().skip(1);
    if let Some(path) = args.next() {
        read_from_path(&path)
    } else {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    }
}

/// Parse a JSON string into a `BanEntry`.
pub fn parse_ban_entry(raw: &str) -> Result<BanEntry, String> {
    serde_json::from_str::<BanEntry>(raw).map_err(|e| format!("{e}"))
}

/// Read from a file path and parse as `BanEntry`.
pub fn run_from_path(path: &str) -> Result<BanEntry, String> {
    let raw = read_from_path(path).map_err(|e| format!("read input: {e}"))?;
    parse_ban_entry(&raw)
}

/// Read input and parse as `BanEntry`.
pub fn run() -> Result<BanEntry, String> {
    let raw = read_input().map_err(|e| format!("read input: {e}"))?;
    parse_ban_entry(&raw)
}

/// Drift guard against `provii-verifier/src/storage/ban_store.rs::BanEntry`.
///
/// The bin re-declares `BanEntry`
/// independently of the lib because the lib targets wasm32 with worker deps
/// that are not native-buildable. If the lib's struct grows a required
/// field, these tests mirror the canonical fixtures in `ban_store.rs::tests`
/// so any structural drift surfaces in CI as a parse failure here.
///
/// Keep these fixtures in lock-step with `ban_store.rs::tests`. Update both
/// or neither.
#[cfg(test)]
mod tests {
    use super::BanEntry;

    /// Mirrors `ban_store.rs::tests::test_ban_entry_deserialize_full`. Full
    /// payload with all four fields populated.
    #[test]
    fn test_decode_full_shape_mirrors_lib_fixture() {
        let json = r#"{"reason":"test","banned_at":9999,"expires_at":10000,"banned_by":"op"}"#;
        let entry: BanEntry = serde_json::from_str(json).expect("full fixture must parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(entry.reason, "test");
        assert_eq!(entry.banned_at, 9999);
        assert_eq!(entry.expires_at, Some(10000));
        assert_eq!(entry.banned_by, "op");
    }

    /// Mirrors
    /// `ban_store.rs::tests::test_ban_entry_accepts_provii_management_ts_write_shape`.
    /// The exact JSON the provii-management TS write path emits.
    #[test]
    fn test_decode_provii_management_ts_write_shape_mirrors_lib_fixture() {
        let json = r#"{"reason":"abuse","banned_at":1727000000000,"expires_at":1727086400000,"banned_by":"admin@example.com"}"#;
        let entry: BanEntry = serde_json::from_str(json).expect("TS-shape fixture must parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(entry.reason, "abuse");
        assert_eq!(entry.banned_at, 1_727_000_000_000);
        assert_eq!(entry.expires_at, Some(1_727_086_400_000));
        assert_eq!(entry.banned_by, "admin@example.com");
    }

    /// Mirrors `ban_store.rs::tests::test_ban_entry_deserialize_no_expiry`.
    /// `expires_at` is optional; absence parses as `None`.
    #[test]
    fn test_decode_no_expiry_mirrors_lib_fixture() {
        let json = r#"{"reason":"perma","banned_at":1727000000000,"banned_by":"admin"}"#;
        let entry: BanEntry = serde_json::from_str(json).expect("no-expiry fixture must parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(entry.reason, "perma");
        assert_eq!(entry.banned_at, 1_727_000_000_000);
        assert!(entry.expires_at.is_none());
        assert_eq!(entry.banned_by, "admin");
    }

    /// Mirrors
    /// `ban_store.rs::tests::test_ban_entry_deserialize_explicit_null_expiry`.
    /// `"expires_at": null` parses as `None`.
    #[test]
    fn test_decode_explicit_null_expiry_mirrors_lib_fixture() {
        let json = r#"{"reason":"x","banned_at":1,"expires_at":null,"banned_by":"a"}"#;
        let entry: BanEntry = serde_json::from_str(json).expect("null-expiry fixture must parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert!(entry.expires_at.is_none());
    }

    /// Mirrors `ban_store.rs::tests::test_ban_entry_rejects_legacy_shape`.
    /// The pre-fix `{reason, timestamp}` shape must NOT parse; pins the
    /// no-migration policy. If the lib relaxes this, the bin must too.
    #[test]
    fn test_decode_rejects_legacy_shape_mirrors_lib_fixture() {
        let json = r#"{"reason":"old","timestamp":1234}"#;
        let result = serde_json::from_str::<BanEntry>(json);
        assert!(result.is_err(), "legacy shape must not parse");
    }

    /// Mirrors `ban_store.rs::tests::test_ban_entry_tolerates_unknown_fields`.
    /// Unknown fields are tolerated. Guards against future TS-side
    /// additions causing silent ban drops on the bin path.
    #[test]
    fn test_decode_tolerates_unknown_fields_mirrors_lib_fixture() {
        let json = r#"{"reason":"x","banned_at":1,"banned_by":"a","future_field":"yes"}"#;
        let entry: BanEntry = serde_json::from_str(json).expect("unknown-field fixture must parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(entry.reason, "x");
        assert_eq!(entry.banned_at, 1);
        assert_eq!(entry.banned_by, "a");
    }

    /// Drift sentinel. If the lib's `BanEntry` adds a required field, this
    /// minimal fixture (only the four current required fields populated)
    /// must continue to parse here OR be updated when the lib is updated.
    /// The pairing fails CI when the lib's tests still pass against the
    /// updated struct but the bin's struct is stale.
    #[test]
    fn test_decode_minimal_required_fields_drift_sentinel() {
        let json = r#"{"reason":"r","banned_at":0,"banned_by":"b"}"#;
        let entry: BanEntry =
            serde_json::from_str(json).expect("minimal-required fixture must parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(entry.reason, "r");
        assert_eq!(entry.banned_at, 0);
        assert!(entry.expires_at.is_none());
        assert_eq!(entry.banned_by, "b");
    }

    /// Verify `parse_ban_entry` returns an error for invalid JSON.
    #[test]
    fn test_parse_ban_entry_invalid_json() {
        let result = super::parse_ban_entry("not json");
        assert!(result.is_err());
    }

    /// Verify `parse_ban_entry` succeeds for valid input.
    #[test]
    fn test_parse_ban_entry_valid() {
        let json = r#"{"reason":"r","banned_at":1,"banned_by":"b"}"#;
        let entry = super::parse_ban_entry(json).expect("valid json must parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(entry.reason, "r");
    }

    /// Verify `parse_ban_entry` error message contains serde detail.
    #[test]
    fn test_parse_ban_entry_error_message_contains_detail() {
        let result = super::parse_ban_entry("{}");
        assert!(result.is_err());
        let msg = result.err().expect("should be err"); // nosemgrep: provii.workers.expect-on-external-input
        assert!(
            msg.contains("reason"),
            "error should mention missing field: {msg}"
        );
    }

    /// Verify `parse_ban_entry` rejects JSON array input.
    #[test]
    fn test_parse_ban_entry_rejects_array() {
        let result = super::parse_ban_entry("[]");
        assert!(result.is_err());
    }

    // =======================================================================
    // read_from_path tests (filesystem-backed)
    // =======================================================================

    /// `read_from_path` reads valid file contents.
    #[test]
    fn test_read_from_path_valid_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("ban_entry_test_valid.json");
        let json = r#"{"reason":"r","banned_at":1,"banned_by":"b"}"#;
        std::fs::write(&path, json).expect("write temp file"); // nosemgrep: provii.workers.expect-on-external-input
        let contents = super::read_from_path(path.to_str().expect("path to str")) // nosemgrep: provii.workers.expect-on-external-input
            .expect("should read file"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(contents, json);
        let _ = std::fs::remove_file(&path);
    }

    /// `read_from_path` returns an error for a nonexistent file.
    #[test]
    fn test_read_from_path_nonexistent() {
        let result = super::read_from_path("/tmp/ban_entry_test_does_not_exist_12345.json");
        assert!(result.is_err());
    }

    // =======================================================================
    // run_from_path tests (end-to-end file -> parse)
    // =======================================================================

    /// `run_from_path` successfully reads and parses a valid file.
    #[test]
    fn test_run_from_path_valid() {
        let dir = std::env::temp_dir();
        let path = dir.join("ban_entry_test_run_valid.json");
        let json = r#"{"reason":"abuse","banned_at":1727000000000,"expires_at":1727086400000,"banned_by":"admin@example.com"}"#;
        std::fs::write(&path, json).expect("write temp file"); // nosemgrep: provii.workers.expect-on-external-input
        let entry = super::run_from_path(path.to_str().expect("path to str")) // nosemgrep: provii.workers.expect-on-external-input
            .expect("should parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(entry.reason, "abuse");
        assert_eq!(entry.banned_at, 1_727_000_000_000);
        assert_eq!(entry.expires_at, Some(1_727_086_400_000));
        assert_eq!(entry.banned_by, "admin@example.com");
        let _ = std::fs::remove_file(&path);
    }

    /// `run_from_path` returns an error for a nonexistent file.
    #[test]
    fn test_run_from_path_nonexistent_file() {
        let result = super::run_from_path("/tmp/ban_entry_test_run_no_such_file.json");
        assert!(result.is_err());
        let msg = result.err().expect("should be err"); // nosemgrep: provii.workers.expect-on-external-input
        assert!(
            msg.contains("read input:"),
            "error should be from read step: {msg}"
        );
    }

    /// `run_from_path` returns an error for invalid JSON in file.
    #[test]
    fn test_run_from_path_invalid_json() {
        let dir = std::env::temp_dir();
        let path = dir.join("ban_entry_test_run_invalid.json");
        std::fs::write(&path, "not json").expect("write temp file"); // nosemgrep: provii.workers.expect-on-external-input
        let result = super::run_from_path(path.to_str().expect("path to str")); // nosemgrep: provii.workers.expect-on-external-input
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }

    /// `run_from_path` returns an error for empty file.
    #[test]
    fn test_run_from_path_empty_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("ban_entry_test_run_empty.json");
        std::fs::write(&path, "").expect("write temp file"); // nosemgrep: provii.workers.expect-on-external-input
        let result = super::run_from_path(path.to_str().expect("path to str")); // nosemgrep: provii.workers.expect-on-external-input
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }
}
