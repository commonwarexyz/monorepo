#!/usr/bin/env bash
# Shared helpers for stability checks.
# Sourced by both check-stability (justfile) and find_unstable_public.sh.

# Crates to exclude: examples, internal tooling, heavy external deps, fuzz targets, proc-macro crates
SKIP_REGEX="commonware-bridge|commonware-chat|commonware-estimator|commonware-flood|commonware-log|commonware-sync|commonware-reshare|commonware-conformance|commonware-deployer|-fuzz$|-macros$"

# Public items to ignore (#[macro_export] macros can't be inside stability_scope due to Rust limitations)
IGNORE_ITEMS="NZDuration|NZU8|NZU16|NZU32|NZU64|NZUsize"

# Returns --exclude flags for cargo commands
stability_exclude_flags() {
    cargo metadata --no-deps --format-version=1 2>/dev/null | \
        jq -r '.packages[].name' | \
        grep -E "$SKIP_REGEX" | \
        sed 's/^/--exclude /' | \
        tr '\n' ' '
}
