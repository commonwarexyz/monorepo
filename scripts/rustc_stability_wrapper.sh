#!/usr/bin/env bash

# Wrapper that injects stability cfg flags only for workspace crates.
# Used by `just check-stability` to avoid recompiling dependencies.
#
# Usage: COMMONWARE_STABILITY_LEVEL=BETA RUSTC_WORKSPACE_WRAPPER=scripts/rustc_stability_wrapper.sh cargo check
#
# The justfile creates level-specific symlinks to this script (wrapper_BETA, etc.)
# so Cargo sees different wrapper paths and correctly invalidates caches per level.
#
# The justfile saves RUSTC_WRAPPER into COMMONWARE_RUSTC_WRAPPER and clears it
# to avoid Cargo nesting ($RUSTC_WRAPPER $RUSTC_WORKSPACE_WRAPPER $RUSTC), which
# breaks tools like sccache that can't identify the wrapper as a compiler. Instead,
# this script invokes the original RUSTC_WRAPPER internally, reversing the order.
if [ -n "$COMMONWARE_RUSTC_WRAPPER" ]; then
    exec "$COMMONWARE_RUSTC_WRAPPER" "$@" --cfg "commonware_stability_${COMMONWARE_STABILITY_LEVEL}"
else
    exec "$@" --cfg "commonware_stability_${COMMONWARE_STABILITY_LEVEL}"
fi
