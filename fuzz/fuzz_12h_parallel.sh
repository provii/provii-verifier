#!/bin/bash
# Run all provii-verifier fuzz targets in parallel for 12 hours
# This script distributes available CPU cores among all targets

set -euo pipefail

DURATION=$((12 * 3600))  # 12 hours in seconds
TARGETS=(
    "fuzz_input_validation"
    "fuzz_hmac_auth"
    "fuzz_jwks_parsing"
)

# Detect available CPU cores
if [[ "$OSTYPE" == "darwin"* ]]; then
    TOTAL_CORES=$(sysctl -n hw.ncpu)
else
    TOTAL_CORES=$(nproc)
fi

# Divide cores among targets (at least 1 per target)
NUM_TARGETS=${#TARGETS[@]}
JOBS_PER_TARGET=$(( (TOTAL_CORES + NUM_TARGETS - 1) / NUM_TARGETS ))
JOBS_PER_TARGET=$((JOBS_PER_TARGET > 0 ? JOBS_PER_TARGET : 1))

echo "=================================================="
echo "12-Hour Parallel Fuzzing Campaign (provii-verifier)"
echo "=================================================="
echo "Total CPU cores: $TOTAL_CORES"
echo "Targets: ${NUM_TARGETS}"
echo "Jobs per target: $JOBS_PER_TARGET"
echo "Duration: 12 hours"
echo "Start time: $(date)"
echo "=================================================="

# Create corpus and output directories if they don't exist
for target in "${TARGETS[@]}"; do
    mkdir -p "corpus/$target"
    mkdir -p "artifacts/$target"
done

# Function to run a single fuzz target
run_fuzz_target() {
    local target=$1
    local jobs=$2
    local duration=$3

    echo "[$(date)] Starting $target with $jobs jobs for $duration seconds..."

    cargo +nightly fuzz run "$target" \
        --jobs="$jobs" \
        -- \
        -max_total_time="$duration" \
        -timeout=30 \
        -rss_limit_mb=4096 \
        -print_final_stats=1 \
        2>&1 | tee "fuzz_output_${target}.log"

    echo "[$(date)] Finished $target"
}

# Launch all targets in parallel
pids=()
for target in "${TARGETS[@]}"; do
    run_fuzz_target "$target" "$JOBS_PER_TARGET" "$DURATION" &
    pids+=($!)
done

echo ""
echo "All fuzz targets launched. PIDs: ${pids[*]}"
echo "Waiting for completion (12 hours)..."
echo ""

# Wait for all background jobs to complete
for pid in "${pids[@]}"; do
    wait "$pid" || echo "Warning: Target with PID $pid exited with non-zero status"
done

echo ""
echo "=================================================="
echo "Fuzzing campaign complete!"
echo "End time: $(date)"
echo "=================================================="
echo ""
echo "Check fuzz_output_*.log for detailed results"
echo "Check artifacts/ for any discovered crashes"
