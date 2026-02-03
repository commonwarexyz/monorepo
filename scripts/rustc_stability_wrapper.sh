#!/usr/bin/env bash
# Wrapper that injects stability cfg flags only for workspace crates.
# Used by `just check-stability` to avoid recompiling dependencies.
#
# Usage: COMMONWARE_STABILITY_LEVEL=BETA RUSTC_WORKSPACE_WRAPPER=scripts/rustc_stability_wrapper.sh cargo check
#
# The justfile creates level-specific symlinks to this script (wrapper_BETA, etc.)
# so Cargo sees different wrapper paths and correctly invalidates caches per level.
exec "$@" --cfg "commonware_stability_${COMMONWARE_STABILITY_LEVEL}"
