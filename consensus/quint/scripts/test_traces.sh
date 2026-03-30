#!/usr/bin/env bash
# Run quint model checker on generated trace files.
# On failure, copies the .qnt test and its source .json trace
# into tracing_crashes/ under the quint directory.
#
# Usage:
#   ./scripts/test_traces.sh [test_dir_or_file [traces_root]]
#
# Environment:
#   OUT_ITF_DIR  - if set, emit ITF traces to this directory
#                  (file: $OUT_ITF_DIR/trace_roundtrip_test_<corpus>.itf.json)
#
# Defaults:
#   test_dir_or_file = traces
#   traces_root      = ../fuzz/artifacts/traces

set -euo pipefail

TEST_TARGET="${1:-traces}"
TRACES_ROOT="${2:-../fuzz/artifacts/traces}"
MAX_LINES=4000
PASS=0
FAIL=0
SKIP=0
TOTAL=0

if [ -f "$TEST_TARGET" ]; then
    TEST_FILES=("$TEST_TARGET")
elif [ -d "$TEST_TARGET" ]; then
    TEST_FILES=("$TEST_TARGET"/trace_*.qnt)
else
    echo "Error: $TEST_TARGET does not exist"
    exit 1
fi

if [ -d "$TEST_TARGET" ]; then
    TRACE_ROOT_DIR="$TEST_TARGET"
else
    TRACE_ROOT_DIR="$(dirname "$TEST_TARGET")"
fi
CRASHES_DIR="${TRACE_ROOT_DIR}/crashes"

QUINT_BIN="$(which quint)"
TRACE_SELECTION_STRATEGY="${TRACE_SELECTION_STRATEGY:-current}"

case "$TRACE_SELECTION_STRATEGY" in
    smallscope | short | lof)
        MAX_SAMPLES=5
        ;;
    current | default)
        MAX_SAMPLES=10000
        ;;
    *)
        echo "Error: unsupported TRACE_SELECTION_STRATEGY=$TRACE_SELECTION_STRATEGY"
        exit 1
        ;;
esac

for qnt_file in "${TEST_FILES[@]}"; do
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
    cmd=("$quint_bin" test --main=tests --backend=rust "--max-samples=$MAX_SAMPLES" --verbosity=4 --match=traceTest)
    if [ -n "${OUT_ITF_DIR:-}" ]; then
        mkdir -p "$OUT_ITF_DIR"
        basename_noext=$(basename "$qnt_file" .qnt)
        corpus_itf="${basename_noext#trace_}"
        cmd+=(--out-itf="$OUT_ITF_DIR/trace_roundtrip_test_${corpus_itf}.itf.json")
    fi
    cmd+=("$qnt_file")
    if NODE_OPTIONS="--max-old-space-size=$heap_mb" "${cmd[@]}"; then
        PASS=$((PASS + 1))
        if [ "$(dirname "$qnt_file")" = "$TRACE_ROOT_DIR" ]; then
          trace_count=$(find "$TRACE_ROOT_DIR" -maxdepth 1 -type f -name 'trace_*.qnt' | wc -l)
          if [ "$trace_count" -gt 3 ]; then
              rm -f "$qnt_file"
          fi
        fi
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: $qnt_file"

        # Extract corpus hash from filename: trace_<hash>.qnt -> <hash>
        basename=$(basename "$qnt_file" .qnt)
        corpus_hash="${basename#trace_}"

        # Move failed .qnt and copy source .json into traces/crashes so the
        # relative imports in the qnt file still resolve from consensus/quint.
        mkdir -p "$CRASHES_DIR"
        mv "$qnt_file" "$CRASHES_DIR/"

        # Find the source JSON in any subdirectory of traces_root
        json_file=$(find "$TRACES_ROOT" -name "${corpus_hash}.json" 2>/dev/null | head -1)
        if [ -n "$json_file" ]; then
            cp "$json_file" "$CRASHES_DIR/"
            echo "Copied crash artifacts to $CRASHES_DIR"
        else
            echo "Warning: source JSON not found for $corpus_hash"
        fi
    fi
done

if [ "$TOTAL" -eq 0 ]; then
    echo "No trace_*.qnt files found in $TEST_TARGET"
    exit 0
fi

echo ""
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped, $TOTAL total"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
