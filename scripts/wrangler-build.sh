#!/usr/bin/env bash
# Custom wrangler [build] command (referenced from wrangler.toml [build]).
#
# Normal `wrangler dev` / local builds: build the Worker wasm as before.
# Production deploy: CI sets PROVII_SKIP_WORKER_BUILD=1 so this NO-OPS, because the
# signed, attested artifact is already in build/ (downloaded from the
# build-wasm-production job) and MUST NOT be rebuilt and discarded.
#
# We gate on an EXPLICIT CI var, not on WRANGLER_COMMAND: WRANGLER_COMMAND is
# undocumented and varies across wrangler versions, so relying on it would fail
# OPEN (a silent rebuild that discards the signed bytes) on an upgrade. This var
# fails CLOSED: the no-op only happens when we explicitly ask for it.
set -euo pipefail

if [ -n "${PROVII_SKIP_WORKER_BUILD:-}" ]; then
  echo "wrangler-build: PROVII_SKIP_WORKER_BUILD set -> deploying the pre-built artifact in build/ as-is (no rebuild)."
  # Fail LOUD if the pre-built artifact is not actually present, rather than
  # silently shipping an empty/partial bundle.
  if [ ! -f build/worker/shim.mjs ] || [ ! -f build/index_bg.wasm ] || [ ! -f build/index.js ]; then
    echo "ERROR: PROVII_SKIP_WORKER_BUILD set but build/ is missing shim.mjs, index_bg.wasm, or index.js (shim.mjs imports ../index.js)." >&2
    exit 1
  fi
  exit 0
fi

# Local / dev path. Pinned to match CI (0.7.5); the canonical reproducible build
# is scripts/reproducible-build.sh.
cargo install -q worker-build@0.7.5
worker-build --release
