#!/bin/bash
# Lint and format checking
set -eo pipefail
cd "$(dirname "$0")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[lint]${NC} $1"; }
success() { echo -e "${GREEN}[lint]${NC} $1"; }
error() { echo -e "${RED}[lint]${NC} $1" >&2; exit 1; }

show_help() {
    cat <<EOF
Usage: ./lint.sh [OPTIONS]

Lint and format Rust code across all workspaces.

Options:
  --check    Check formatting only (don't fix) - for CI
  --help     Show this help

Examples:
  ./lint.sh           # Fix formatting in place
  ./lint.sh --check   # Check only (CI mode)
EOF
}

CHECK_FLAG=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)
            CHECK_FLAG="--check"
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

if [[ -n "$CHECK_FLAG" ]]; then
    log "Checking format (CI mode)..."
else
    log "Fixing format..."
fi

# Format main workspace
log "Formatting main workspace..."
cargo +nightly fmt -- $CHECK_FLAG

# Format fuzz workspace
log "Formatting fuzz workspace..."
cargo +nightly fmt --manifest-path fuzz/Cargo.toml -- $CHECK_FLAG

# Format afl workspace
log "Formatting afl workspace..."
cargo +nightly fmt --manifest-path afl/Cargo.toml -- $CHECK_FLAG

success "All formatting ${CHECK_FLAG:+checks }complete"
