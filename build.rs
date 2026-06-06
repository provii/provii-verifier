// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Compile-time guard against shipping sandbox-only code in a production
//! build.
//!
//! The `sandbox_only_register_test_issuer_client` Cargo feature exists
//! in provii-verifier as a mirror of the provii-issuer flag so that any
//! sandbox-surface code paths added to the verifier (cross-linked to
//! docs-sandbox issuer clients) can be gated in the same way. Like the
//! provii-issuer counterpart, this feature MUST NOT ship in the production
//! wasm bundle.
//!
//! Two independent defences protect production:
//!
//! 1. **Cargo feature** (this file). Production CI invokes
//!    `worker-build --release` with the feature omitted. If someone
//!    passes `--features sandbox_only_register_test_issuer_client`
//!    while the `PROVII_ENV` environment variable is `production`,
//!    this build script aborts compilation with a `cargo::error`.
//! 2. **CI prod-bundle grep**. A post-build step reads the
//!    released wasm and fails if `register-test-issuer-client` or
//!    `docs-sbx-` string literals or high-entropy Ed25519 seed-shaped
//!    strings are present.
//!
//! # Why `PROVII_ENV` and NOT `CARGO_CFG_PROVII_ENV`
//!
//! Cargo reserves the `CARGO_CFG_*` namespace for build-script outputs
//! corresponding to `--cfg` flags. Setting `CARGO_CFG_PROVII_ENV` as a
//! plain shell env var in CI does NOT propagate through Cargo to the
//! build-script process the way an ordinary env var does, so the guard
//! silently failed to fire (W4-S5 regression). The
//! sentinel must be a plain env var name with no Cargo-reserved prefix.
//!
//! # Rebuild triggers
//!
//! This script reruns if `PROVII_ENV` changes or the feature flag is
//! toggled. Other env var changes do not invalidate the build.

fn main() {
    println!("cargo:rerun-if-env-changed=PROVII_ENV");
    println!("cargo:rerun-if-changed=build.rs");

    let provii_env = std::env::var("PROVII_ENV").unwrap_or_default();
    let sandbox_feature_enabled =
        std::env::var("CARGO_FEATURE_SANDBOX_ONLY_REGISTER_TEST_ISSUER_CLIENT").is_ok();

    if sandbox_feature_enabled && provii_env == "production" {
        println!(
            "cargo::error=refusing to build provii-verifier for production \
             with `sandbox_only_register_test_issuer_client` feature \
             enabled. This would link sandbox-surface code paths into \
             the production verifier. Remove --features \
             sandbox_only_register_test_issuer_client from the production \
             build invocation, or unset PROVII_ENV if this is a sandbox \
             build. See compile-time guard / W4-S5."
        );
    }
}
