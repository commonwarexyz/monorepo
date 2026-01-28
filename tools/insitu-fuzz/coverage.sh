#!/usr/bin/env bash
set -euo pipefail

# Get script directory and use it as root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect target triple
TARGET_TRIPLE="${TARGET_TRIPLE:-$(rustc -vV | awk '/host:/ {print $2}')}"

# Note: cargo-fuzz puts profdata in fuzz/ but binary in root target/
PROFDATA="fuzz/coverage/all_tests/coverage.profdata"
BINARY="target/$TARGET_TRIPLE/coverage/$TARGET_TRIPLE/release/all_tests"
OUTPUT_DIR="coverage_html"

# Check dependencies
command -v llvm-cov >/dev/null || {
    echo "❌ llvm-cov not found. Install: rustup component add llvm-tools --toolchain nightly"
    exit 1
}

command -v rustfilt >/dev/null || {
    echo "❌ rustfilt not found. Install: cargo install rustfilt"
    exit 1
}

# Check required files
[[ -f "$PROFDATA" ]] || {
    echo "❌ Run first: cargo +nightly fuzz coverage all_tests"
    exit 1
}

[[ -f "$BINARY" ]] || {
    echo "❌ Binary not found at: $BINARY"
    exit 1
}

# Generate report
echo "Generating coverage report..."
llvm-cov show "$BINARY" \
  -Xdemangler=rustfilt \
  -instr-profile="$PROFDATA" \
  --ignore-filename-regex='.*cargo/registry.*' \
  --ignore-filename-regex='.*rustup/toolchains.*' \
  -show-line-counts-or-regions \
  -show-instantiations \
  -format=html \
  -output-dir="$OUTPUT_DIR"

echo "✅ Done: file://$SCRIPT_DIR/$OUTPUT_DIR/index.html"
