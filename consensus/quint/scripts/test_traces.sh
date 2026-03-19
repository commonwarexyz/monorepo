#!/usr/bin/env bash
# Run quint model checker on generated trace files.
# On failure, copies the .qnt test and its source .json trace
# into ../fuzz/crashes/traces/<corpus_hash>/.
#
# Usage:
#   ./scripts/test_traces.sh [test_dir [traces_root]]
#
# Defaults:
#   test_dir    = traces
#   traces_root = ../fuzz/artifacts/traces

set -euo pipefail

TEST_DIR="${1:-traces}"
TRACES_ROOT="${2:-../fuzz/artifacts/traces}"
CRASHES_DIR="../fuzz/artifacts/tracing_crashes/"
MAX_LINES=1900
PASS=0
FAIL=0
SKIP=0
TOTAL=0

if [ ! -d "$TEST_DIR" ]; then
    echo "Error: directory $TEST_DIR does not exist"
    exit 1
fi

QUINT_BIN="$(which quint)"

for qnt_file in "$TEST_DIR"/trace_*.qnt; do
    [ -f "$qnt_file" ] || continue
    TOTAL=$((TOTAL + 1))
    lines=$(wc -l < "$qnt_file")
    if [ "$lines" -gt "$MAX_LINES" ]; then
        echo "Skipping (too large, $lines lines): $qnt_file"
        SKIP=$((SKIP + 1))
        continue
    fi
    echo "Testing: $qnt_file"
    heap_mb=24576
    quint_bin="$(command -v quint)"
    cmd=("$quint_bin" test --main=tests --backend=rust --verbosity=4 --match=traceTest "$qnt_file")
    if NODE_OPTIONS="--max-old-space-size=$heap_mb" "${cmd[@]}"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: $qnt_file"

        # Extract corpus hash from filename: trace_<hash>.qnt -> <hash>
        basename=$(basename "$qnt_file" .qnt)
        corpus_hash="${basename#trace_}"

        # Copy failed .qnt and source .json to crashes directory
        crash_dir="$CRASHES_DIR/$corpus_hash"
        mkdir -p "$crash_dir"
        cp "$qnt_file" "$crash_dir/"

        # Find the source JSON in any subdirectory of traces_root
        json_file=$(find "$TRACES_ROOT" -name "${corpus_hash}.json" 2>/dev/null | head -1)
        if [ -n "$json_file" ]; then
            cp "$json_file" "$crash_dir/"
            echo "Copied crash artifacts to $crash_dir"
        else
            echo "Warning: source JSON not found for $corpus_hash"
        fi
    fi
done

if [ "$TOTAL" -eq 0 ]; then
    echo "No trace_*.qnt files found in $TEST_DIR"
    exit 0
fi

echo ""
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped, $TOTAL total"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
