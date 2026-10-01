#!/usr/bin/env bash
# Verifies the balance-only epoch arithmetic with Verus.
#
# Point VERUS_BIN at a Verus release binary. Before relying on the result, review
# close_kernel.rs against transition.rs::derive's balance/output block and
# transition.rs::checked_successor_liability as described in README.md.
# This script verifies the model, not its correspondence to production Rust.
set -euo pipefail
VERUS_BIN="${VERUS_BIN:-verus}"
exec "$VERUS_BIN" --crate-type=lib "$(dirname "$0")/close_kernel.rs"
