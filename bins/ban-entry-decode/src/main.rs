// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! `ban-entry-decode`. Cross-language BanEntry JSON shape harness.
//!
//! Paired with the provii-management Vitest at
//! `provii-management/tests/rotation/banentry-schema.test.ts`. That test captures
//! the JSON `addToBanlist` writes to KV, hands it to this binary as a file
//! path, and asserts a clean exit.
//!
//! ## Usage
//!
//! ```text
//! ban-entry-decode <path-to-json>      # reads the file
//! echo '{...}' | ban-entry-decode      # reads stdin if no arg given
//! ```
//!
//! On success: prints the four fields one `key=value` per line in this order:
//! `reason`, `banned_at`, `expires_at` (literal `null` when absent),
//! `banned_by`. Exit 0.
//!
//! On parse failure: writes the `serde_json` error to stderr, exits 1.

use provii_verifier_ban_entry_decode::run;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(entry) => {
            println!("reason={}", entry.reason);
            println!("banned_at={}", entry.banned_at);
            match entry.expires_at {
                Some(v) => println!("expires_at={v}"),
                None => println!("expires_at=null"),
            }
            println!("banned_by={}", entry.banned_by);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ban-entry-decode: {e}");
            ExitCode::FAILURE
        }
    }
}
