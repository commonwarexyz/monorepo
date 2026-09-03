#!/usr/bin/env bash
# Verifies the sender-vector kernels with Verus.
#
# Point VERUS_BIN at a Verus release binary (https://github.com/verus-lang/verus/releases;
# the release pins its own rustc via rustup). The exec bodies in close_kernel.rs mirror
# posted::derive_successor and Prefix::checked_extend: diff them against the crate when
# either side changes.
set -euo pipefail
VERUS_BIN="${VERUS_BIN:-verus}"
exec "$VERUS_BIN" --crate-type=lib "$(dirname "$0")/close_kernel.rs"
