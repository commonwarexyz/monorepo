#!/usr/bin/env bash
# Publish one crate to crates.io.
#
# A version that is already on crates.io counts as success, so this can run on
# every push to main. Any other failure fails the step.
#
# Usage: publish_crate.sh <path to Cargo.toml>

set -uo pipefail

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

cargo publish --manifest-path "$1" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}

if [ "$status" -ne 0 ] && grep -q 'already exists on crates.io index' "$log"; then
    echo "Already published, skipping."
    exit 0
fi
exit "$status"
