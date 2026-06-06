#!/bin/bash
# Run a single provii-verifier fuzz target for 12 hours
# Usage: ./fuzz_12h_individual.sh <target_name>

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <target_name>"
    echo ""
    echo "Available targets:"
    echo "  - fuzz_input_validation"
    echo "  - fuzz_hmac_auth"
    echo "  - fuzz_jwks_parsing"
    exit 1
fi

TARGET=$1
DURATION=$((12 * 3600))  # 12 hours in seconds

# Detect available CPU cores
if [[ "$OSTYPE" == "darwin"* ]]; then
    JOBS=$(sysctl -n hw.ncpu)
else
    JOBS=$(nproc)
fi

echo "=================================================="
echo "12-Hour Individual Fuzzing Campaign"
echo "=================================================="
echo "Target: $TARGET"
echo "CPU cores: $JOBS"
echo "Duration: 12 hours"
echo "Start time: $(date)"
echo "=================================================="

# Create corpus and output directories if they don't exist
mkdir -p "corpus/$TARGET"
mkdir -p "artifacts/$TARGET"

# Run the fuzz target
echo ""
echo "[$(date)] Starting $TARGET..."
echo ""

cargo +nightly fuzz run "$TARGET" \
    --jobs="$JOBS" \
    -- \
    -max_total_time="$DURATION" \
    -timeout=30 \
    -rss_limit_mb=4096 \
    -print_final_stats=1 \
    2>&1 | tee "fuzz_output_${TARGET}.log"

echo ""
echo "=================================================="
echo "Fuzzing complete!"
echo "End time: $(date)"
echo "=================================================="
echo ""
echo "Check fuzz_output_${TARGET}.log for detailed results"
echo "Check artifacts/$TARGET for any discovered crashes"
