#!/usr/bin/env bash
set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required but not installed." >&2
    exit 1
fi

cargo metadata --no-deps --format-version=1 2>/dev/null | \
    jq -r '
        .packages[]
        | select(.manifest_path | test("/examples/|/fuzz/") | not)
        | select(any(.targets[]; any(.kind[]; . == "lib" or . == "rlib" or . == "cdylib" or . == "dylib" or . == "proc-macro")))
        | .name
    ' | \
    sort -u
