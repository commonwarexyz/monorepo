#!/usr/bin/env bash
# Run quint model checker on generated trace files.
#
# Usage:
#   ./consensus/scripts/test_traces.sh [test_dir]
#
# Defaults to consensus/quint/traces/ if no directory is specified.

set -euo pipefail

TEST_DIR="${1:-traces}"
PASS=0
FAIL=0
TOTAL=0

if [ ! -d "$TEST_DIR" ]; then
    echo "Error: directory $TEST_DIR does not exist"
    exit 1
fi

for qnt_file in "$TEST_DIR"/trace_*.qnt; do
    [ -f "$qnt_file" ] || continue
    TOTAL=$((TOTAL + 1))
    echo "Testing: $qnt_file"
    if quint test --main=tests "$qnt_file"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: $qnt_file"
    fi
done

if [ "$TOTAL" -eq 0 ]; then
    echo "No trace_*.qnt files found in $TEST_DIR"
    exit 0
fi

echo ""
echo "Results: $PASS passed, $FAIL failed, $TOTAL total"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
