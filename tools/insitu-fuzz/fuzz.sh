#!/bin/bash
# Fuzz testing harness with corpus generation
set -eo pipefail
cd "$(dirname "$0")"

# Fuzz target selection
FUZZ_TARGET="fast_tests"  # Default: fast tests only (<100ms)
FUZZ_DIR="fuzz"

# cargo-fuzz flags (applied to both build and run)
# --sanitizer=none: Disable ASAN for faster builds (safe Rust doesn't need it)
FUZZ_FLAGS="--sanitizer=none"

# Get available targets from fuzz/Cargo.toml (all [[bin]] names)
AVAILABLE_TARGETS=$(grep -A1 '^\[\[bin\]\]' "$FUZZ_DIR/Cargo.toml" | grep '^name' | sed 's/.*"\(.*\)".*/\1/' | tr '\n' ' ')

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() { echo -e "${BLUE}[fuzz.sh]${NC} $*" >&2; }
success() { echo -e "${GREEN}✓${NC} $*" >&2; }
error() { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

# Production directory for cron jobs
PROD_DIR="$HOME/insitu-fuzz-prod"
DEV_DIR="$HOME/insitu-fuzz"

# Run cron job: update, setup, fuzz
run_cron() {
    # Fast setup: copy .git from dev, checkout, update submodules
    rm -rf "$PROD_DIR"
    mkdir -p "$PROD_DIR"
    cp -r "$DEV_DIR/.git" "$PROD_DIR/"
    cd "$PROD_DIR"
    git checkout .
    git submodule update --init --recursive
    ./setup.sh clean
    # Clean .git to save space (after setup since it uses git commands)
    rm -rf .git
    timeout 8h ./fuzz.sh --target=fast_tests run
}

# Install cron job
setup_cron() {
    local existing
    existing=$(crontab -l 2>/dev/null || echo "")

    (
        echo "$existing" | grep -v "insitu-fuzz-prod" || true
        echo "0 0 * * * PATH=\$HOME/.cargo/bin:\$PATH $DEV_DIR/fuzz.sh run_cron >> \$HOME/insitu-fuzz-cron.log 2>&1"
    ) | crontab -

    success "Cron job installed: daily 8-hour fuzzing at midnight"
    log "Production dir: $PROD_DIR"
    log "Verify: crontab -l"
}

show_help() {
    cat <<EOF
Usage: ./fuzz.sh [--target=TARGET] <command> [MSG_IDX]

Commands:
  build           Build fuzz target only (no fuzzing)
  run [MSG_IDX]   Fuzz all messages or specific message
  test            Run fuzzer tests only
  corpus          Generate corpus seeds
  clean           Wipe corpus directory
  cron            Install daily 8-hour cron job

Targets (--target=):
  $AVAILABLE_TARGETS
  (default: fast_tests)

Examples:
  ./fuzz.sh run                           # Fuzz fast tests (default)
  ./fuzz.sh run 50                        # Fuzz message 50
  ./fuzz.sh --target=fast_tests run       # Fuzz only fast tests
  ./fuzz.sh --target=simplex run          # Fuzz simplex test only
  ./fuzz.sh corpus                        # Generate seeds for all unique message lengths
  ./fuzz.sh clean                         # Clean corpus
  ./fuzz.sh test                          # Run fuzzer tests
EOF
}

# Helper to create seed with proper format
make_seed() {
    local test_sel=$1
    local msg_idx=$2
    local length=$3

    if [[ "$FUZZ_TARGET" == "all_tests" ]]; then
        # Format: [test_selector: u16][msg_idx: u16][padding][0x01]
        printf "\\x$(printf %02x $((test_sel & 0xFF)))\\x$(printf %02x $((test_sel >> 8)))"
        printf "\\x$(printf %02x $((msg_idx & 0xFF)))\\x$(printf %02x $((msg_idx >> 8)))"
        [[ $length -gt 4 ]] && head -c $((length - 5)) /dev/zero 2>/dev/null || true
    else
        # Format: [msg_idx: u16][padding][0x01]
        printf "\\x$(printf %02x $((msg_idx & 0xFF)))\\x$(printf %02x $((msg_idx >> 8)))"
        [[ $length -gt 2 ]] && head -c $((length - 3)) /dev/zero 2>/dev/null || true
    fi
    printf "\\x01"
}

# Generate corpus seeds - reads message_counts.json to create seeds for unique message lengths
generate_corpus() {
    local msg_idx="${1:-0}"
    local corpus_dir="$FUZZ_DIR/corpus/$FUZZ_TARGET"
    local msg_counts_file="tools/message_counts.json"

    log "Generating corpus seeds for target '$FUZZ_TARGET'..."
    mkdir -p "$corpus_dir"

    if [[ ! -f "$msg_counts_file" ]]; then
        error "$msg_counts_file not found"
    fi

    # Dynamically determine number of tests from JSON file
    local total_tests=$(tail -n +2 "$msg_counts_file" | wc -l)
    local max_tests=$([[ "$FUZZ_TARGET" == "all_tests" ]] && echo "$total_tests" || echo 1)

    # Use single jq call to extract all seed data (test_idx:msg_idx:length)
    local seed_data=$(tail -n +2 "$msg_counts_file" | head -n "$max_tests" | jq -r --slurp '
        to_entries |
        .[] |
        .key as $test_idx |
        .value.lengths |
        to_entries |
        group_by(.value) |
        map({test_idx: $test_idx, msg_idx: .[0].key, length: .[0].value}) |
        .[] |
        "\(.test_idx):\(.msg_idx):\(.length)"
    ')

    local total_seeds=0
    local max_test_idx=0
    if [[ "$FUZZ_TARGET" == "all_tests" ]]; then
        while IFS=: read -r test_idx msg_idx len; do
            make_seed "$test_idx" "$msg_idx" "$len" > "$corpus_dir/seed_t${test_idx}_len${len}"
            (( ++total_seeds ))
            max_test_idx=$test_idx
        done <<< "$seed_data"
    else
        while IFS=: read -r test_idx msg_idx len; do
            make_seed "$test_idx" "$msg_idx" "$len" > "$corpus_dir/seed_len${len}"
            (( ++total_seeds ))
            max_test_idx=$test_idx
        done <<< "$seed_data"
    fi

    success "Generated $total_seeds seeds across $((max_test_idx + 1)) test(s)"
}

# Run fuzzer tests to ensure fuzzing infrastructure works
run_fuzzer_tests() {
    log "Running fuzzer tests..."
    cargo test --lib fuzzer_test --features test-registry -- --test-threads=1
    success "All fuzzer tests passed"
}

# Run standard fuzzing
run_fuzzing() {
    local msg_idx="$1"
    local max_len="8192"

    log "Using fuzz target: $FUZZ_TARGET"
    log "Fuzzing ${msg_idx:+message $msg_idx with }max_len=$max_len..."

    if [[ -n "$msg_idx" ]]; then
        (cd "$FUZZ_DIR" && MSG_IDX=$msg_idx cargo fuzz run $FUZZ_FLAGS "$FUZZ_TARGET" -- -max_len="$max_len")
    else
        (cd "$FUZZ_DIR" && cargo fuzz run $FUZZ_FLAGS "$FUZZ_TARGET" -- -max_len="$max_len")
    fi

    success "Fuzzing completed"
}

# Main logic
main() {
    # Parse --target flag
    while [[ "$1" == --* ]]; do
        case "$1" in
            --target=*)
                FUZZ_TARGET="${1#*=}"
                if [[ ! " $AVAILABLE_TARGETS " =~ " $FUZZ_TARGET " ]]; then
                    error "Invalid target: $FUZZ_TARGET (valid: $AVAILABLE_TARGETS)"
                fi
                shift
                ;;
            *)
                error "Unknown flag: $1"
                ;;
        esac
    done

    local mode="${1:-}"
    local msg_idx="${2:-}"
    local corpus_dir="$FUZZ_DIR/corpus/$FUZZ_TARGET"

    # Show help if no args
    [[ -z "$mode" ]] && show_help && exit 0

    case "$mode" in
        cron)
            setup_cron
            ;;
        run_cron)
            run_cron
            ;;
        test)
            run_fuzzer_tests
            ;;
        corpus)
            generate_corpus "$msg_idx"
            ;;
        clean)
            if [[ -d "$corpus_dir" ]]; then
                rm -rf "$corpus_dir"
                success "Corpus removed for $FUZZ_TARGET"
            else
                log "No corpus for $FUZZ_TARGET"
            fi
            ;;
        build)
            log "Building all fuzz targets..."
            for target in $AVAILABLE_TARGETS; do
                log "  Building $target..."
                (cd "$FUZZ_DIR" && cargo fuzz build $FUZZ_FLAGS "$target")
            done
            success "All targets built"
            ;;
        run)
            log "Skipping corpus generation (see usage)..."
            run_fuzzing "$msg_idx"
            ;;
        *)
            error "Unknown command: $mode (run ./fuzz.sh for help)"
            ;;
    esac
}

main "$@"
