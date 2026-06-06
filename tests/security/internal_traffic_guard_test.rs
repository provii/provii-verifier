// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Structural test: every `/_internal/` route handler must call
//! `reject_external_internal_traffic` as its first guard.
//!
//! This catches regressions where a new internal route is added without
//! the external traffic rejection check. The test reads the router source
//! at compile time via `include_str!` and verifies the invariant.

#![forbid(unsafe_code)]
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::string_slice,
    clippy::panic
)]

use wasm_bindgen_test::*;

/// The router source embedded at compile time.
const ROUTER_SOURCE: &str = include_str!("../../src/worker_routes.rs");

/// Verify that every `/_internal/` route registration is followed (within
/// its handler body) by a call to `reject_external_internal_traffic`.
///
/// Strategy: find each line containing a route path with `/_internal/`, then
/// scan forward up to 12 lines for the guard call. Twelve lines is generous
/// enough to cover the closure signature, header extraction, and the guard
/// block itself.
#[wasm_bindgen_test]
fn all_internal_routes_call_reject_external_internal_traffic() {
    let lines: Vec<&str> = ROUTER_SOURCE.lines().collect();
    let route_patterns = [
        "\"/_internal/version\"",
        "\"/_internal/invalidate-jwks\"",
        "\"/_internal/mek-decrypt-probe\"",
        "\"/_internal/replay-saved-pre-rotation-token\"",
        "\"/_internal/test-fixtures\"",
        "\"/_internal/test-fixtures/:class\"",
    ];

    for pattern in &route_patterns {
        // Find the line registering this route.
        let route_line = lines
            .iter()
            .position(|l| l.contains(pattern))
            .unwrap_or_else(|| panic!("Route {} not found in worker_routes.rs", pattern));

        // Scan forward up to 12 lines for the guard call.
        let window_end = (route_line + 12).min(lines.len());
        let window = &lines[route_line..window_end];
        let has_guard = window
            .iter()
            .any(|l| l.contains("reject_external_internal_traffic"));

        assert!(
            has_guard,
            "Route {} (line {}) does not call reject_external_internal_traffic within \
             the first 12 lines of its handler. All /_internal/ routes MUST call the \
             guard before any other logic.",
            pattern,
            route_line + 1
        );
    }
}

/// Verify that no new `/_internal/` route exists without being listed in
/// the known set above. If a developer adds a sixth internal route, this
/// test forces them to add it to the structural check as well.
#[wasm_bindgen_test]
fn no_unlisted_internal_routes() {
    let known_routes: &[&str] = &[
        "\"/_internal/version\"",
        "\"/_internal/invalidate-jwks\"",
        "\"/_internal/mek-decrypt-probe\"",
        "\"/_internal/replay-saved-pre-rotation-token\"",
        "\"/_internal/test-fixtures\"",
        "\"/_internal/test-fixtures/:class\"",
    ];

    // Find route registrations: lines containing a quoted `/_internal/` path.
    // The path string is the definitive marker of a route registration,
    // whether or not `_async(` appears on the same line.
    let route_registrations: Vec<(usize, &str)> = ROUTER_SOURCE
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("\"/_internal/") && l.contains('"'))
        .filter(|(_, l)| {
            // Exclude comments and doc strings.
            let trimmed = l.trim();
            !trimmed.starts_with("//") && !trimmed.starts_with("///")
        })
        .collect();

    for (line_num, line) in &route_registrations {
        let is_known = known_routes.iter().any(|r| line.contains(r));
        assert!(
            is_known,
            "Unlisted internal route found at line {}: {}\n\
             Add it to both the `all_internal_routes_call_reject_external_internal_traffic` \
             and `no_unlisted_internal_routes` tests.",
            line_num + 1,
            line.trim()
        );
    }

    // Sanity: we should find at least 6 registrations.
    assert!(
        route_registrations.len() >= 6,
        "Expected at least 6 internal route registrations, found {}. \
         The detection heuristic may need updating.",
        route_registrations.len()
    );
}
