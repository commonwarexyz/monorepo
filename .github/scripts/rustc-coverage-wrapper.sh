#!/bin/bash
# Rustc wrapper that adds coverage instrumentation flags.
# Used via RUSTC_WORKSPACE_WRAPPER to instrument only workspace crates.
# See .github/workflows/coverage.yml for details.
exec "$1" -C instrument-coverage --cfg=coverage --cfg=trybuild_no_target "${@:2}"
