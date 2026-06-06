#!/bin/bash
# Run all provii-verifier fuzz targets sequentially, 12 hours each
# Total time: 36 hours (3 targets × 12 hours)

set -euo pipefail

DURATION=$((12 * 3600))  # 12 hours in seconds
TARGETS=(
    "fuzz_input_validation"
    "fuzz_hmac_auth"
    "fuzz_jwks_parsing"
)

# Detect available CPU cores for parallel execution within each target
if [[ "$OSTYPE" == "darwin"* ]]; then
    JOBS=$(sysctl -n hw.ncpu)
else
    JOBS=$(nproc)
fi

echo "=================================================="
echo "12-Hour Sequential Fuzzing Campaign (provii-verifier)"
echo "=================================================="
echo "Total CPU cores: $JOBS"
echo "Targets: ${#TARGETS[@]}"
echo "Duration per target: 12 hours"
echo "Total campaign time: 36 hours"
echo "Start time: $(date)"
echo "=================================================="

# Create corpus and output directories if they don't exist
for target in "${TARGETS[@]}"; do
    mkdir -p "corpus/$target"
    mkdir -p "artifacts/$target"
done

# Run each target sequentially
for target in "${TARGETS[@]}"; do
    echo ""
    echo "=================================================="
    echo "[$(date)] Running $target for $DURATION seconds..."
    echo "=================================================="

    cargo +nightly fuzz run "$target" \
        --jobs="$JOBS" \
        -- \
        -max_total_time="$DURATION" \
        -timeout=30 \
        -rss_limit_mb=4096 \
        -print_final_stats=1 \
        2>&1 | tee "fuzz_output_${target}.log"

    echo ""
    echo "[$(date)] Completed $target"
done

echo ""
echo "=================================================="
echo "All fuzzing targets complete!"
echo "End time: $(date)"
echo "=================================================="
echo ""
echo "Check fuzz_output_*.log for detailed results"
echo "Check artifacts/ for any discovered crashes"
