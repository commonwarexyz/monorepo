set positional-arguments := true

alias f := fix-fmt
alias l := lint
alias b := build
alias t := test
alias pr := pre-pr

# default recipe to display help information
default:
    @just --list

# Build the workspace
build *args='':
    cargo build $@

# Runs pre-flight lints + tests before making a pull-request
pre-pr: lint test-docs test

# Fixes the formatting of the workspace
fix-fmt nightly_version='+nightly':
    cargo {{ nightly_version }} fmt --all

# Fixes the formatting of the `Cargo.toml` files in the workspace
fix-toml-fmt:
   find . -name Cargo.toml -type f -print0 | xargs -0 -n1 ./.github/scripts/lint_cargo_toml.py

# Check the formatting of the workspace
check-fmt nightly_version='+nightly':
    cargo {{ nightly_version }} fmt --all -- --check

# Run clippy lints
clippy *args='':
    cargo clippy --all-targets $@ -- -D warnings

# Runs all lints (fmt, clippy, and docs.)
lint: check-fmt clippy check-docs

# Tests benchmarks in a given crate
test-benches crate *args='':
    cargo test --benches -p {{ crate }} {{ args }} -- --verbose

# Run tests
test *args='':
    cargo nextest run $@

# Test the Rust documentation
test-docs *args='--all':
    cargo test --doc --locked $@

# Lint the Rust documentation
check-docs *args='':
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items $@

# Run all fuzz tests in a given directory
fuzz fuzz_dir max_time='60' nightly_version='+nightly' max_mem='4000':
    #!/usr/bin/env bash
    for target in $(cargo {{nightly_version}} fuzz list --fuzz-dir {{fuzz_dir}}); do
        cargo {{nightly_version}} fuzz run $target --fuzz-dir {{fuzz_dir}} -- -max_total_time={{max_time}} -rss_limit_mb={{max_mem}}
    done

# Check for unused dependencies
udeps nightly_version='+nightly':
    cargo {{ nightly_version }} udeps --all-targets

# Run miri tests on a given module
miri module:
    MIRIFLAGS="-Zmiri-disable-isolation" cargo miri test --lib {{ module }}
