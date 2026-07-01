# Insitu-Fuzz Technical Overview

This document describes how Insitu-Fuzz works under the hood and what the
supporting scripts actually do. It is intended as a practical reference for
maintainers and contributors.

## What Insitu-Fuzz Is

Insitu-Fuzz is a fuzzing infrastructure project that turns existing Commonware
tests into fuzz targets. It does this by:
- patching the monorepo to expose tests and add fuzzing hooks
- generating a test registry with message counts and durations
- providing LibFuzzer and AFL++ harnesses that drive real tests
- hooking into runtime internals to mutate messages or task order

## Repository Layout (top-level)

- `setup.sh` applies patches and generates the registry
- `tools/message_counts.sh` measures per-test message counts and durations
- `scripts/patch_tests.sh`/`patch_tests.py` add `#[fuzzable_test]`
- `scripts/gen_test_registry.py` generates `src/test_registry.rs`
- `src/` contains the fuzzing library and hooks
- `fuzz/` contains LibFuzzer targets (cargo-fuzz)
- `afl/` contains AFL++ targets (cargo-afl)
- `patches/` + `patches/raw/` contain monorepo patch material

## Core Data Flow

1. Generate message counts:
   - `tools/message_counts.sh` runs tests with `MSG_INFO=1` and writes
     `tools/message_counts.json` and `tools/message_lengths.json`.
2. Patch tests and generate registry:
   - `scripts/patch_tests.sh` applies bulk edits, adds `#[fuzzable_test]`,
     then runs `scripts/gen_test_registry.py` to emit `src/test_registry.rs`.
3. Build fuzzing artifacts:
   - LibFuzzer targets in `fuzz/` and AFL++ targets in `afl/` compile against
     the registry and the patched monorepo.
4. Run fuzzers:
   - `fuzz.sh` or `afl.sh` choose a target and drive the test using inputs.

## How `setup.sh` Works

`setup.sh` is the orchestrator:
- Assumes it runs inside the Commonware monorepo (no submodules).
- Optionally cleans or pulls the monorepo.
- Applies patches:
  - Copies replacement files from `patches/raw/`.
  - Applies patch files in `patches/*.patch`.
- Runs `scripts/patch_tests.sh` to add fuzzable attributes and generate the
  registry.
- Optionally runs `./fuzz.sh test`.

## How `tools/message_counts.sh` Works

This script measures message counts and durations for tests:
- Runs `cargo +nightly nextest run` with `MSG_INFO=1`.
- The patched `p2p` codec records message counts and lengths at exit.
- `tools/parse_junit.py` reads nextest JUnit output and writes
  `tools/message_counts.json` (one JSON object per line).
- Counts and durations are later used to build the test registry and drive
  message corruption bounds.

## How `scripts/patch_tests.sh` Works

`patch_tests.sh` applies bulk edits and generates a registry:
- Rewrites `#[cfg(test)]` and `#[cfg(feature = "mocks")]` to include `fuzzing`.
- Makes test modules public (`mod tests` -> `pub mod tests`).
- Adds `fuzzing = []` to Cargo.toml files (and wires `rstest` where needed).
- Adds `#[fuzzable_test]` to selected tests via `scripts/patch_tests.py`.
- Generates `src/test_registry.rs` via `scripts/gen_test_registry.py`.

## How the Registry Works

`src/test_registry.rs` is auto-generated from `message_counts.json`. Each entry
contains:
- a test name string
- `message_count`
- `duration_ms`
- a function pointer to the test function

Harnesses select a test by index and call it directly with fuzzing hooks set up.

## Runtime and Codec Hooks

Fuzzing hooks are exposed via weak-linkage FFI so they can be overridden by
`insitu-fuzz` at link time:
- Message mutation:
  - `commonware_fuzz_corrupt_bytes(ptr, len)` is called from the `p2p` codec.
- Task order fuzzing:
  - `commonware_fuzz_permute_tasks(ids, len)` is called in the deterministic
    runtime before task execution.
- AFL deferred fork:
  - `insitu_fuzz_checkpoint()` is called at runtime quiescent points.

## LibFuzzer Targets (`fuzz/`)

Targets in `fuzz/fuzz_targets/` consume input and drive registry tests.
Typical formats:
- multi-test message mutation:
  `[test_selector:u16][msg_idx:u16][xor_key...]`
- single-test message mutation:
  `[msg_idx:u16][xor_key...]`
- task order:
  `[test_selector:u16][task_order_bytes...]` or `[task_order_bytes...]`

`fuzz.sh` wraps cargo-fuzz with convenience commands:
- `run`: start fuzzing
- `corpus`: generate seed corpus from `message_counts.json`
- `test`: run fuzzer unit/integration tests
- `cron`: install a nightly run

## AFL++ Targets (`afl/`)

Targets in `afl/src/bin/` mirror LibFuzzer plus additional deferred-fork
targets:
- `single_range` and `reshare_restart` use `MSG_IDX` to fork late.
- `task_order_reshare` fuzzes task order for a large reshare test.

`afl.sh` wraps cargo-afl with target selection, benchmarking, and parallel
execution.

## Panic Filtering (Test Oracle)

`build.rs` generates `test_oracle.txt` by scanning the monorepo for test spans.
`setup_panic_hook()` uses this oracle to filter panics from test code and
infrastructure. Panics in production code abort and are reported as findings.

## Useful Environment Variables

- `MSG_INFO=1`:
  enable message counting during test runs (for registry generation).
- `MSG_IDX=...`:
  restrict message mutation or deferred fork ranges in AFL++.
- `TEST_IDX=...`:
  select a specific test by index (AFL single_range).
- `TASK_ORDER_DEBUG=1`:
  log task ordering decisions to `/tmp/task_order.log`.
- `FAST_TEST_MODE=1`:
  enable fast crypto bypass (from `fast_crypto.patch`).

## Typical Workflows

### Refresh the Registry After Monorepo Changes
1. `bash tools/message_counts.sh --all`
2. `./setup.sh`

### Quick Fuzz Run (LibFuzzer)
1. `./setup.sh`
2. `./fuzz.sh run`

### Focused AFL Run with Deferred Fork
1. `./setup.sh`
2. `TEST_IDX=40 MSG_IDX=100 ./afl.sh --target=single_range run`
