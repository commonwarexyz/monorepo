#!/bin/bash
# Measure message counts and duration for tests in the monorepo
# Outputs to commonware-fuzz/tools/message_counts.json
#
# Usage: ./message_counts.sh [OPTIONS]
#   (no args)    - Run on resolver crate only (fast tests only)
#   --all        - Run on all crates (fast tests only)
#   --slow       - Run on all crates, all tests (including ignored/slow tests)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FUZZ_DIR="$SCRIPT_DIR/.."  # insitu-fuzz directory
MONOREPO_DIR="$FUZZ_DIR/../.."  # monorepo directory

OUTPUT_FILE="$SCRIPT_DIR/message_counts.json"
LENGTHS_FILE="$SCRIPT_DIR/message_lengths.json"

# Run from monorepo to access all workspace crates
cd "$MONOREPO_DIR"

# Parse arguments
CRATE_SCOPE="-p commonware-resolver"  # Default: resolver only
RUN_IGNORED=""  # Default: fast tests only
NEXTEST_PROFILE="default"  # Uses filter: not test(/.*_slow_$/)
MODE_DESC="resolver crate only (fast tests only)"

if [[ "$1" == "--slow" ]]; then
    CRATE_SCOPE=""
    RUN_IGNORED="--run-ignored all"
    NEXTEST_PROFILE="all"  # Uses filter: test(/.*/) - includes _slow_ tests
    MODE_DESC="all crates, all tests including slow tests"
    echo "Running all tests including slow tests on all crates..." >&2
elif [[ "$1" == "--all" ]]; then
    CRATE_SCOPE=""
    MODE_DESC="all crates (fast tests only, excludes _slow_ tests)"
    echo "Running all crates (fast tests only, use --slow to include slow tests)..." >&2
elif [[ -z "$1" ]]; then
    echo "Running resolver crate only (use --all for all crates, --slow for slow tests)..." >&2
else
    echo "Unknown option: $1" >&2
    echo "Usage: $0 [--all|--slow]" >&2
    exit 1
fi

echo "Measuring message counts for $MODE_DESC..." >&2

# Detect available CPU cores and set test threads
NCPU=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo "8")
TEST_THREADS_PER_SEED=${TEST_THREADS:-$((NCPU * 2))}

# Run all tests in PARALLEL with final output (buffered per-test)
# Each test runs in separate process so MSG_COUNT won't bleed between tests
# Set MSG_INFO env var to trigger automatic reporting via atexit()
# Filter out utility packages that don't use network mocks to avoid rare misattribution

# Build and display the command
CARGO_CMD="cargo +nightly nextest run $CRATE_SCOPE $RUN_IGNORED --features fuzzing --test-threads=$TEST_THREADS_PER_SEED --success-output final --failure-output final"
echo "" >&2
echo "Executing: MSG_INFO=1 $CARGO_CMD" >&2
echo "" >&2

# Get current commit hash from monorepo
COMMIT_HASH=$(git rev-parse HEAD)
echo "Monorepo commit: $COMMIT_HASH" >&2

# Write commit metadata as first line
echo "{\"_metadata\":{\"commit\":\"$COMMIT_HASH\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}}" > "$OUTPUT_FILE"

# Run tests and generate JUnit XML (continue even if tests fail)
# Our config includes merged test-groups/filters from monorepo + JUnit settings
MSG_INFO=1 cargo +nightly nextest run \
    $CRATE_SCOPE $RUN_IGNORED --features fuzzing \
    --test-threads=$TEST_THREADS_PER_SEED \
    --profile "$NEXTEST_PROFILE" \
    --config-file "$FUZZ_DIR/.config/nextest.toml" 2>&1 >/dev/null || true

# Parse JUnit XML and append results (lengths go to separate file)
JUNIT_XML="$MONOREPO_DIR/target/nextest/$NEXTEST_PROFILE/junit.xml"
python3 "$FUZZ_DIR/tools/parse_junit.py" "$JUNIT_XML" --lengths-file "$LENGTHS_FILE" >> "$OUTPUT_FILE"

TEST_COUNT=$(($(wc -l < "$OUTPUT_FILE") - 1))
echo "✓ Generated $OUTPUT_FILE with $TEST_COUNT test entries (commit: $COMMIT_HASH)" >&2
