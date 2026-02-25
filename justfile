set positional-arguments := true

env_nightly_version := env("NIGHTLY_VERSION", "nightly")
nightly_version := if env_nightly_version != "" { "+" + env_nightly_version } else { "" }
rustfmt := env("RUSTFMT", "rustfmt")

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
fix-fmt *args='':
    find . -path ./target -prune -o -name '*.rs' -type f -print0 | xargs -0 {{ rustfmt }} {{ nightly_version }} --edition 2021 {{ args }}

# Fixes the formatting of the `Cargo.toml` files in the workspace
fix-toml-fmt:
    find . -name Cargo.toml -type f -print0 | xargs -0 -n1 ./.github/scripts/lint_cargo_toml.py

# Check Cargo.toml formatting without keeping modifications
check-toml-fmt:
    find . -name Cargo.toml -type f -print0 | xargs -0 -n1 ./.github/scripts/lint_cargo_toml.py --check

# Check the formatting of the workspace
check-fmt:
    just fix-fmt --check

# Run clippy lints
clippy *args='':
    cargo clippy --all-targets $@ -- -D warnings

# Fix clippy lints
fix-clippy *args='':
    cargo clippy --all-targets --fix --allow-dirty $@

# Runs all lints (fmt, clippy, docs, features, toml, benchmark names, and stability)
lint: check-fmt check-toml-fmt clippy check-docs check-features check-benchmark-names check-stability

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

# Lint benchmark naming conventions
check-benchmark-names:
    python3 .github/scripts/lint_benchmark_names.py

# Run all fuzz tests in a given directory
fuzz fuzz_dir max_time='60' max_mem='4000':
    #!/usr/bin/env bash
    for target in $(cargo {{nightly_version}} fuzz list --fuzz-dir {{fuzz_dir}}); do
        cargo {{nightly_version}} fuzz run $target --fuzz-dir {{fuzz_dir}} -- -max_total_time={{max_time}} -rss_limit_mb={{max_mem}}
        rm -f {{fuzz_dir}}/target/*/release/$target
    done

# Run cargo-hack with feature powerset
hack *args='':
    cargo hack --feature-powerset --no-dev-deps $@

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

# Test conformance (optionally for specific crates: just test-conformance -p commonware-codec)
test-conformance *args='':
    just test --features arbitrary --profile conformance {{ args }}

# Regenerate conformance fixtures (optionally for specific crates: just regenerate-conformance -p commonware-codec)
regenerate-conformance *args='':
    RUSTFLAGS="--cfg generate_conformance_tests" just test --features arbitrary --profile conformance {{ args }}

# Find public items missing stability annotations.
unstable-public *args='':
    ./scripts/find_unstable_public.sh {{ args }}

# Check stability builds. Optionally specify level (1-4 or BETA/GAMMA/DELTA/EPSILON) and/or crate (-p <crate>).
# ALPHA (level 0) is the default state and doesn't require a cfg flag.
# Examples: just check-stability, just check-stability 3, just check-stability DELTA, just check-stability GAMMA -p commonware-cryptography
check-stability *args='':
    #!/usr/bin/env bash
    all_args="{{ args }}"
    level=""
    extra_args=""
    # Build exclude flags from shared config
    source scripts/stability_helpers.sh
    excludes=$(stability_exclude_flags)
    # Level names in order (index 0-4)
    LEVEL_NAMES=(ALPHA BETA GAMMA DELTA EPSILON)
    # Convert name to index by iterating the array
    name_to_num() {
        for i in "${!LEVEL_NAMES[@]}"; do
            if [ "${LEVEL_NAMES[$i]}" = "$1" ]; then
                echo "$i"
                return
            fi
        done
    }
    # Check if first arg is a level (number 1-4 or name)
    first_arg="${all_args%% *}"
    if [[ "$first_arg" =~ ^[1-4]$ ]]; then
        level="$first_arg"
        extra_args="${all_args#* }"
        if [ "$extra_args" = "$first_arg" ]; then extra_args=""; fi
    else
        num=$(name_to_num "$first_arg")
        if [ -n "$num" ]; then
            if [ "$num" = "0" ]; then
                echo "Error: ALPHA is the default stability level (no cfg flag needed)."
                echo "Use 'cargo build' directly or specify BETA/GAMMA/DELTA/EPSILON."
                exit 1
            fi
            level="$num"
            extra_args="${all_args#* }"
            if [ "$extra_args" = "$first_arg" ]; then extra_args=""; fi
        else
            extra_args="$all_args"
        fi
    fi
    # Create level-specific wrapper symlinks so Cargo sees different fingerprints
    mkdir -p target/stability-wrappers
    for name in "${LEVEL_NAMES[@]:1}"; do
        ln -sf "$(pwd)/scripts/rustc_stability_wrapper.sh" "target/stability-wrappers/wrapper_${name}"
    done
    if [ -z "$level" ]; then
        for name in "${LEVEL_NAMES[@]:1}"; do
            echo "Checking commonware_stability_${name}..."
            COMMONWARE_STABILITY_LEVEL="${name}" RUSTC_WORKSPACE_WRAPPER="target/stability-wrappers/wrapper_${name}" cargo check --workspace --lib $excludes $extra_args || exit 1
        done
        echo "All stability levels pass!"
        echo "Checking for unmarked public items..."
        ./scripts/find_unstable_public.sh $extra_args
    else
        echo "Checking commonware_stability_${LEVEL_NAMES[$level]}..."
        COMMONWARE_STABILITY_LEVEL="${LEVEL_NAMES[$level]}" RUSTC_WORKSPACE_WRAPPER="target/stability-wrappers/wrapper_${LEVEL_NAMES[$level]}" cargo check --workspace --lib $excludes $extra_args
    fi
