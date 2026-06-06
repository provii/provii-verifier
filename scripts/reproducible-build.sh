#!/usr/bin/env bash
# Canonical reproducible build for the Provii verifier Worker wasm.
#
# Goal: produce a bit-identical build/index_bg.wasm across machines, so a third
# party (and our own CI rebuilder) can rebuild a tagged commit and match the
# published deployed hash. This script is the single source of truth for HOW the
# released/deployed wasm is built; CI and VERIFY.md both invoke it.
#
# PREREQUISITES:
#   - Run from the repo root with sibling path-deps present:
#       ../provii-crypto and ../provii-audit (pinned to the same tag CI uses).
#   - The exact toolchain is pinned by rust-toolchain.toml.
#
# IMPORTANT: reproducibility here is an EMPIRICAL target, not an assumption. The
# wasm post-processing chain (wasm-bindgen + wasm-opt) can emit non-reproducible
# output. .github/workflows/reproducibility-check.yml builds twice and diffs; if
# it fails, inspect the section diff and adjust the pins / strip set below. Do
# not trust this script until that job is green.
set -euo pipefail

# --- hermetic environment (the Tor reproducible-build playbook) ---
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"   # separate assign: don't mask git's exit code under set -e
export SOURCE_DATE_EPOCH
export LC_ALL=C
export TZ=UTC
export CARGO_INCREMENTAL=0

# --- path remapping (reproducibility), wasm32-target-scoped ---
# Scope rustflags to the wasm32 target ONLY. A global CARGO_ENCODED_RUSTFLAGS leaks
# +bulk-memory onto host build-scripts/proc-macros ("'+bulk-memory' is not a
# recognized feature for this target"); the target-scoped env var applies only to
# wasm32, mirroring .cargo/config.toml's [target.wasm32-unknown-unknown]. We restate
# +bulk-memory because this env var replaces the config-file rustflags for wasm32.
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="-Ctarget-feature=+bulk-memory --remap-path-prefix=${HOME}=/home --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=${PWD}=/build"

# --- exact tool pins ---
# worker-build pinned EXACTLY (CI currently floats "0.7.5"; "=" makes it exact).
WORKER_BUILD_VERSION="0.7.5"
# wasm-bindgen-cli MUST byte-match the wasm-bindgen LIBRARY version in Cargo.lock,
# so derive it from the lockfile rather than hardcoding (keeps them in lockstep).
WASM_BINDGEN_VERSION="$(awk '/^name = "wasm-bindgen"$/{getline; v=$3; gsub(/"/,"",v); print v; exit}' Cargo.lock)"
# wasm-opt / Binaryen output changes across versions. Paste the exact
# `wasm-opt --version` output below to enforce the pin (leave empty to skip with
# a warning on first run, then set it).
EXPECTED_WASM_OPT_VERSION=""

echo "Pins: worker-build=$WORKER_BUILD_VERSION wasm-bindgen-cli=$WASM_BINDGEN_VERSION SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"

cargo install worker-build --version "=$WORKER_BUILD_VERSION" --locked
cargo install wasm-bindgen-cli --version "=$WASM_BINDGEN_VERSION" --locked

if [ -n "$EXPECTED_WASM_OPT_VERSION" ]; then
  if [ "$(wasm-opt --version)" != "$EXPECTED_WASM_OPT_VERSION" ]; then
    echo "ERROR: wasm-opt version mismatch (reproducibility not guaranteed)." >&2
    echo "  expected: $EXPECTED_WASM_OPT_VERSION" >&2
    echo "  got     : $(wasm-opt --version)" >&2
    exit 1
  fi
else
  echo "WARNING: EXPECTED_WASM_OPT_VERSION unset; wasm-opt pin NOT enforced. Set it after first run." >&2
fi

# --- build ---
# Build via worker-build only (matches the production build exactly). We do NOT add
# a separate `cargo build --locked`: it surfaced a stale committed Cargo.lock (the
# normal build tolerates it without --locked). For STRICT reproducibility, regenerate
# and commit a fresh Cargo.lock, then a --locked build is exact.
worker-build --release

# --- no post-build wasm-opt strip ---
# Take worker-build's output as-is. Re-running wasm-opt to strip `producers` failed
# validation because the module uses bulk-memory (wasm-opt rejects it without
# --enable-bulk-memory). `producers` is deterministic given the pinned tool
# versions, so it should not break reproducibility. If the A-vs-B diff in
# reproducibility-check shows a custom section differing, add a targeted strip here
# with the matching --enable-<feature> flags.

echo "wasm sha256:"
sha256sum build/index_bg.wasm
