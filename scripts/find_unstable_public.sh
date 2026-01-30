#!/usr/bin/env bash
# Finds public items that lack stability annotations by generating rustdoc JSON at MAX level.
#
# At MAX level, all stability-marked items are excluded. Any public items that
# appear in rustdoc JSON are unmarked and need stability annotations.
#
# Usage: ./scripts/find_unstable_public.sh [crate-name...]
#        If no crate specified, checks all workspace library crates.

set -euo pipefail

STABILITY_CFG="commonware_stability_RESERVED"

# Crates to skip (examples, fuzz crates, internal tooling)
# deployer is skipped because it has heavy AWS SDK dependencies
SKIP_REGEX="commonware-bridge|commonware-chat|commonware-estimator|commonware-flood|commonware-log|commonware-sync|commonware-reshare|commonware-conformance|commonware-deployer|-fuzz$|-macros$"

# Items to ignore (#[macro_export] macros can't be inside stability_scope due to Rust limitations)
IGNORE_ITEMS="NZDuration|NZU8|NZU16|NZU32|NZU64|NZUsize"

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed." >&2
    exit 1
fi

# Get list of library crates (includes "lib", "rlib", "cdylib" target kinds)
get_crates() {
    if [[ $# -gt 0 ]]; then
        echo "$@"
    else
        cargo metadata --no-deps --format-version=1 2>/dev/null | \
            jq -r '.packages[] | select(.targets[] | .kind[] | . == "lib" or . == "rlib" or . == "cdylib") | .name' | \
            grep -Ev "$SKIP_REGEX" | \
            sort -u
    fi
}

check_crate() {
    local crate="$1"
    local crate_underscore="${crate//-/_}"
    
    echo "=== Checking $crate ===" >&2
    
    # Generate rustdoc JSON at RESERVED stability level
    # Use both RUSTFLAGS and RUSTDOCFLAGS for consistent cfg propagation
    # Allow broken intra-doc links since stability-gated types won't be available
    if ! RUSTFLAGS="--cfg $STABILITY_CFG" \
        RUSTDOCFLAGS="-Z unstable-options --output-format json --cfg $STABILITY_CFG -Arustdoc::broken_intra_doc_links" \
        cargo +nightly doc -p "$crate" --no-deps 2>/dev/null; then
        echo "  Warning: Could not generate rustdoc for $crate" >&2
        return 1
    fi
    
    # Find the JSON file
    local json_file
    json_file=$(find target/doc -name "${crate_underscore}.json" 2>/dev/null | head -1)
    
    if [[ -z "$json_file" || ! -f "$json_file" ]]; then
        echo "  Warning: No JSON output found for $crate" >&2
        return 1
    fi
    
    # Extract public items (excluding the crate root and ignored items)
    local items
    items=$(jq -r --arg crate "$crate_underscore" --arg ignore "$IGNORE_ITEMS" '
        [.index | to_entries[] | 
         select(.value.visibility == "public") | 
         select(.value.name != null) |
         select(.value.name != $crate) |
         select(.value.name | test($ignore) | not) |
         "\(.value.span.filename // "unknown"):\(.value.span.begin[0] // "?"): \(.value.name)"] | 
        sort | .[]
    ' "$json_file" 2>/dev/null)
    
    if [[ -z "$items" ]]; then
        echo "  OK: No unmarked public items found" >&2
        return 0
    else
        echo "  Found unmarked public items:" >&2
        echo "$items" | sed 's/^/    /'
        return 1
    fi
}

echo "Finding public items without #[stability(...)] markers..."
echo "Using rustdoc JSON at --cfg $STABILITY_CFG"
echo ""

exit_code=0
for crate in $(get_crates "$@"); do
    if ! check_crate "$crate"; then
        exit_code=1
    fi
    echo ""
done

if [[ $exit_code -eq 0 ]]; then
    echo "All public items have stability annotations."
else
    echo "Some crates have unmarked public items (see above)."
    echo ""
    echo "To fix, wrap public items with one of:"
    echo "  - #[stability(LEVEL)] for individual items"
    echo "  - stability_scope!(LEVEL { ... }) for groups of items"
    echo "  - stability_mod!(LEVEL, pub mod name) for modules"
    echo "  - Manual #[cfg(not(any(..., commonware_stability_RESERVED)))] for #[macro_export] macros"
    echo ""
    echo "See README.md for stability level definitions."
fi

exit $exit_code
