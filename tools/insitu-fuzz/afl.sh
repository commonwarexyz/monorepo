#!/bin/bash
# AFL++ fuzzing harness
set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/afl"

# Get test count from registry (dynamic, not hardcoded)
# Use sed for macOS compatibility (no grep -P)
NUM_TESTS=$(sed -n 's/.*pub const NUM_TESTS: usize = \([0-9]*\).*/\1/p' "$SCRIPT_DIR/src/test_registry.rs" 2>/dev/null || echo "0")
MAX_TEST_IDX=$((NUM_TESTS - 1))

# Get available targets from Cargo.toml (all [[bin]] names)
AVAILABLE_TARGETS=$(grep -A1 '^\[\[bin\]\]' Cargo.toml | grep '^name' | sed 's/.*"\(.*\)".*/\1/' | tr '\n' ' ')

TIMEOUT="${TIMEOUT:-5000}"
CORPUS_DIR="corpus"
FINDINGS_DIR="findings"

# Default to 50% of available CPUs (nproc on Linux, sysctl on macOS)
TOTAL_CPUS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
DEFAULT_CPUS=$((TOTAL_CPUS * 5 / 10))
DEFAULT_CPUS=$((DEFAULT_CPUS > 0 ? DEFAULT_CPUS : 1))
PARALLEL="${PARALLEL:-$DEFAULT_CPUS}"

# Target selection (default: fast_tests)
TARGET="fast_tests"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() { echo -e "${BLUE}[afl.sh]${NC} $*" >&2; }
success() { echo -e "${GREEN}✓${NC} $*" >&2; }
error() { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

show_help() {
    cat <<EOF
Usage: ./afl.sh [--target=TARGET] <command> [DURATION]

Commands:
  run                Fuzz with AFL++
  benchmark [SEC]    Run benchmark to test exec/s speed (default: 10s)
  test               Run all fuzzer unit tests
  clean              Remove corpus and findings
  build              Build AFL harnesses only

Targets (--target=): $AVAILABLE_TARGETS
  fast_tests         Fuzz only fast tests (<100ms, default)
  all_tests          Fuzz all $NUM_TESTS tests
  slow_tests         Fuzz only slow tests (>=100ms)
  single_range       Fuzz single test with deferred fork (requires TEST_IDX, MSG_IDX)
  reshare_restart    Fuzz reshare test_restart_threshold (requires MSG_IDX, 134k messages)

Environment:
  TEST_IDX     Target test index 0-$MAX_TEST_IDX (for single_range target)
               See src/test_registry.rs for test indices
  MSG_IDX      Target message index or range (for single_range target)
               Single: "10" targets message 10
               Range: "50..60" targets messages 50-60, exits after 60
  PARALLEL     Number of parallel AFL instances (default: 80% of CPUs = $DEFAULT_CPUS)
  TIMEOUT      AFL timeout in ms (default: 5000)

Examples:
  ./afl.sh run                                             # Fuzz fast tests (default)
  MSG_IDX=1000 ./afl.sh --target=reshare_restart run       # Fuzz reshare restart test
  ./afl.sh benchmark                                       # Benchmark for 10s (default)
  TEST_IDX=5 MSG_IDX=2 ./afl.sh --target=single_range run  # Fork at msg 2, target test 5
  ./afl.sh clean                                           # Remove AFL artifacts
  ./afl.sh build                                           # Just build the harnesses
  ./afl.sh test                                            # Run fuzzer tests
EOF
}

# Run fuzzer unit tests (same tests as fuzz.sh test)
run_tests() {
    log "Running fuzzer tests..."
    (cd .. && cargo test --lib fuzzer_test --features test-registry -- --test-threads=1)
    success "All fuzzer tests passed"
}

# Build AFL harnesses
build_harness() {
    local bin="${1:-$TARGET}"
    log "Building AFL harness ($bin)..."
    cargo afl build --release --bin "$bin"
    success "AFL harness built"
}

# Generate minimal corpus seed if empty
ensure_corpus() {
    if [[ ! -d "$CORPUS_DIR" ]] || [[ -z "$(ls -A $CORPUS_DIR 2>/dev/null)" ]]; then
        log "Generating minimal corpus seed..."
        mkdir -p "$CORPUS_DIR"
        if [[ "$TARGET" == "single_range" ]]; then
            # Single test mode: [msg_idx:u16][xor_key...]
            # Input goes directly to set_fuzzer_input (no test selector)
            local msg_idx="${MSG_IDX%%\.\.*}"  # Extract start of range if range
            printf "\\x$(printf %02x $((msg_idx & 0xFF)))\\x$(printf %02x $((msg_idx >> 8)))\\x01" > "$CORPUS_DIR/seed"
        else
            # Multi-test mode: [test_selector:u16][msg_idx:u16][xor_key...]
            printf '\x00\x00\x00\x00\x01' > "$CORPUS_DIR/seed"
        fi
        success "Corpus seed created"
    fi
}

# Cleanup background jobs on exit/interrupt
cleanup() {
    # Note: macOS xargs doesn't support -r, but handles empty input gracefully
    jobs -p | xargs kill 2>/dev/null || true
}

# Run benchmark to measure exec/s
run_benchmark() {
    local duration="${1:-10}"

    # Build harness
    build_harness "$TARGET"

    # Ensure corpus exists with seeds
    ensure_corpus

    # Use temporary findings directory for isolated benchmark
    local temp_findings=$(mktemp -d)

    # Cleanup temp directory on exit
    trap "rm -rf '$temp_findings'" EXIT INT TERM

    log "Target: $TARGET"

    # Run single instance, No UI, Fixed duration
    export AFL_NO_UI=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

    log "Starting ${duration}s benchmark (Quick & Dirty mode for raw Havoc throughput)..."

    cargo afl fuzz \
        -d \
        -i "$CORPUS_DIR" \
        -o "$temp_findings" \
        -V "$duration" \
        -t "$TIMEOUT" \
        "target/release/$TARGET" > /dev/null 2>&1

    # Parse results
    local stats_file="$temp_findings/default/fuzzer_stats"

    if [[ -f "$stats_file" ]]; then
        local execs_per_sec=$(grep "execs_per_sec" "$stats_file" | awk '{print $3}')
        local execs_total=$(grep "execs_done" "$stats_file" | awk '{print $3}')
        local paths_total=$(grep "paths_total" "$stats_file" | awk '{print $3}')

        echo "========================================" >&2
        success "Benchmark Complete"
        echo "  Duration:      ${duration}s" >&2
        echo -e "  Avg Speed:     ${GREEN}${execs_per_sec} execs/sec${NC}" >&2
        echo "  Total Execs:   ${execs_total}" >&2
        echo "  Total Paths:   ${paths_total}" >&2
        echo "========================================" >&2
    else
        error "Benchmark failed: Could not find stats file at $stats_file"
    fi
}

# Run AFL fuzzer
run_fuzzing() {
    # Build harness
    build_harness "$TARGET"

    # Ensure corpus exists with seeds
    ensure_corpus

    log "Parallel instances: $PARALLEL (CPUs: $TOTAL_CPUS)"
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

    # Set up cleanup trap
    trap cleanup EXIT INT TERM

    # Run AFL
    log "Starting AFL fuzzer ($TARGET)..."
    if [[ "$PARALLEL" -eq 1 ]]; then
        cargo afl fuzz -i "$CORPUS_DIR" -o "$FINDINGS_DIR" -t "$TIMEOUT" "target/release/$TARGET"
    else
        log "Starting $PARALLEL parallel instances (secondaries run in background)..."

        for i in $(seq 1 $((PARALLEL - 1))); do
            cargo afl fuzz -S "s$i" -i "$CORPUS_DIR" -o "$FINDINGS_DIR" -t "$TIMEOUT" "target/release/$TARGET" >/dev/null 2>&1 &
        done

        cargo afl fuzz -M main -i "$CORPUS_DIR" -o "$FINDINGS_DIR" -t "$TIMEOUT" "target/release/$TARGET"
    fi
}

# Main logic
main() {
    # Parse --target flag
    while [[ "$1" == --* ]]; do
        case "$1" in
            --target=*)
                TARGET="${1#*=}"
                if [[ ! " $AVAILABLE_TARGETS " =~ " $TARGET " ]]; then
                    error "Invalid target: $TARGET (valid: $AVAILABLE_TARGETS)"
                fi
                shift
                ;;
            *)
                error "Unknown flag: $1"
                ;;
        esac
    done

    local mode="${1:-}"
    local arg="${2:-}"

    # Show help if no args or help requested
    if [[ -z "$mode" ]] || [[ "$mode" == "-h" ]] || [[ "$mode" == "--help" ]] || [[ "$mode" == "help" ]]; then
        show_help
        exit 0
    fi

    case "$mode" in
        build)
            for target in $AVAILABLE_TARGETS; do
                build_harness "$target"
            done
            ;;
        test)
            run_tests
            ;;
        benchmark)
            run_benchmark "$arg"
            ;;
        clean)
            if [[ -d "$CORPUS_DIR" ]] || [[ -d "$FINDINGS_DIR" ]]; then
                rm -rf "$CORPUS_DIR" "$FINDINGS_DIR"
                success "Removed AFL corpus and findings"
            else
                log "No AFL artifacts to clean"
            fi
            ;;
        run)
            run_fuzzing
            ;;
        *)
            error "Unknown command: $mode (run ./afl.sh for help)"
            ;;
    esac
}

main "$@"
