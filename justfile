set positional-arguments := true

env_nightly_version := env("NIGHTLY_VERSION", "nightly")
nightly_version := if env_nightly_version != "" { "+" + env_nightly_version } else { "" }

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
fix-fmt:
    cargo {{ nightly_version }} fmt --all

# Fixes the formatting of the `Cargo.toml` files in the workspace
fix-toml-fmt:
   find . -name Cargo.toml -type f -print0 | xargs -0 -n1 ./.github/scripts/lint_cargo_toml.py

# Check the formatting of the workspace
check-fmt:
    cargo {{ nightly_version }} fmt --all -- --check

# Run clippy lints
clippy *args='':
    cargo clippy --all-targets $@ -- -D warnings

# Fix clippy lints
fix-clippy *args='':
    cargo clippy --all-targets --fix --allow-dirty $@

# Runs all lints (fmt, clippy, docs, and features.)
lint: check-fmt clippy check-docs check-features

# Fixes all lint issues in the workspace
fix: fix-clippy fix-fmt fix-toml-fmt fix-features

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
fuzz fuzz_dir max_time='60' max_mem='4000':
    #!/usr/bin/env bash
    for target in $(cargo {{nightly_version}} fuzz list --fuzz-dir {{fuzz_dir}}); do
        cargo {{nightly_version}} fuzz run $target --fuzz-dir {{fuzz_dir}} -- -max_total_time={{max_time}} -rss_limit_mb={{max_mem}}
    done

# Check for unused dependencies
udeps:
    cargo {{ nightly_version }} udeps --all-targets

# Run miri tests on a given module
miri module *args='':
    MIRIFLAGS="-Zmiri-disable-isolation" cargo miri nextest run --lib {{ module }} {{ args }}

# Run zepter feature checks
check-features:
    zepter run check && zepter format features

# Fix feature propagation and formatting
fix-features:
    zepter && zepter format features --fix

# Test conformance
test-conformance:
    just test --features arbitrary --profile conformance

# Regenerate conformance fixtures
regenerate-conformance:
    RUSTFLAGS="--cfg generate_conformance_tests" just test --features arbitrary --profile conformance
