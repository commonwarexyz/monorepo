#!/usr/bin/env bash
# Shared configuration for stability checks.
# Sourced by both check-stability (justfile) and find_unstable_public.sh.

# Crates to exclude: examples, internal tooling, heavy external deps, fuzz targets, proc-macro crates
SKIP_REGEX="commonware-bridge|commonware-chat|commonware-estimator|commonware-flood|commonware-log|commonware-sync|commonware-reshare|commonware-conformance|commonware-deployer|-fuzz$|-macros$"

# Returns --exclude flags for cargo commands
stability_exclude_flags() {
    cargo metadata --no-deps --format-version=1 2>/dev/null | \
        jq -r '.packages[].name' | \
        grep -E "$SKIP_REGEX" | \
        sed 's/^/--exclude /' | \
        tr '\n' ' '
}
