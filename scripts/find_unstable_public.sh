#!/usr/bin/env bash
# Finds public items that lack stability annotations by generating rustdoc JSON at MAX level.
#
# At MAX level, all stability-marked items are excluded. Any public items that
# appear in rustdoc JSON are unmarked and need stability annotations.
#
# Usage: ./scripts/find_unstable_public.sh [crate-name...] [-p <crate>] [--package <crate>] [--package=<crate>]
#        If no crate specified, checks all workspace library crates.
#        Unrecognized flags are silently ignored so cargo flags can be forwarded.

set -euo pipefail

STABILITY_CFG="commonware_stability_RESERVED"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/stability_config.sh"

# Items to ignore (#[macro_export] macros can't be inside stability_scope due to Rust limitations)
IGNORE_ITEMS="NZDuration|NZU8|NZU16|NZU32|NZU64|NZUsize"

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed." >&2
    exit 1
fi

usage() {
    cat >&2 <<'EOF'
Usage: ./scripts/find_unstable_public.sh [crate-name...] [-p <crate>] [--package <crate>] [--package=<crate>]
       ./scripts/find_unstable_public.sh [--help]

If no crate is specified, checks all workspace library crates.
Unrecognized flags are silently ignored so cargo flags can be forwarded.
EOF
}

selected_crates=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--package)
            if [[ $# -lt 2 ]]; then
                echo "Error: missing crate name after $1." >&2
                usage
                exit 1
            fi
            selected_crates+=("$2")
            shift 2
            ;;
        --package=*)
            crate="${1#*=}"
            if [[ -z "$crate" ]]; then
                echo "Error: missing crate name in $1." >&2
                usage
                exit 1
            fi
            selected_crates+=("$crate")
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            while [[ $# -gt 0 ]]; do
                selected_crates+=("$1")
                shift
            done
            ;;
        --*=*)
            # Ignore unrecognized --flag=value flags
            shift
            ;;
        -*)
            # Ignore unrecognized flags and consume their value argument
            # (e.g. --features std forwarded from check-stability)
            shift
            if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
                shift
            fi
            ;;
        *)
            selected_crates+=("$1")
            shift
            ;;
    esac
done

# Get list of library crates (includes "lib", "rlib", "cdylib" target kinds)
get_crates() {
    if [[ $# -gt 0 ]]; then
        printf '%s\n' "$@"
    else
        cargo metadata --no-deps --format-version=1 2>/dev/null | \
            jq -r '.packages[] | select(.targets[] | .kind[] | . == "lib" or . == "rlib" or . == "cdylib") | .name' | \
            grep -Ev "$SKIP_REGEX" | \
            sort -u
    fi
}

check_json_file() {
    local json_file="$1"
    local crate_underscore
    crate_underscore=$(basename "$json_file" .json)
    local crate="${crate_underscore//_/-}"
    
    echo "=== Checking $crate ===" >&2
    
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

target_dir="${CARGO_TARGET_DIR:-target}/stability-check"

# Build cargo doc arguments
pkg_args=()
if [[ ${#selected_crates[@]} -gt 0 ]]; then
    # Specific crates requested
    for crate in "${selected_crates[@]}"; do
        pkg_args+=("-p" "$crate")
    done
else
    # All workspace crates (with exclusions)
    read -r -a pkg_args <<< "--workspace $(stability_exclude_flags)"
fi

echo "Generating rustdoc JSON..." >&2

# Generate rustdoc JSON for all crates in a single invocation
# Use RUSTFLAGS and RUSTDOCFLAGS for consistent cfg propagation
# Allow broken intra-doc links since stability-gated types won't be available
if ! RUSTFLAGS="--cfg $STABILITY_CFG" \
    RUSTDOCFLAGS="-Z unstable-options --output-format json --cfg $STABILITY_CFG -Arustdoc::broken_intra_doc_links" \
    CARGO_TARGET_DIR="$target_dir" \
    cargo +nightly doc "${pkg_args[@]}" --no-deps 2>/dev/null; then
    echo "Error: Could not generate rustdoc" >&2
    exit 1
fi

echo ""

# Check each generated JSON file
exit_code=0
while read -r crate; do
    [[ -z "$crate" ]] && continue
    crate_underscore="${crate//-/_}"
    json_file="${target_dir}/doc/${crate_underscore}.json"

    if [[ ! -f "$json_file" ]]; then
        echo "=== Checking $crate ===" >&2
        echo "  Warning: No JSON output found for $crate" >&2
        exit_code=1
        echo ""
        continue
    fi

    if ! check_json_file "$json_file"; then
        exit_code=1
    fi
    echo ""
done < <(get_crates "${selected_crates[@]+"${selected_crates[@]}"}")

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
