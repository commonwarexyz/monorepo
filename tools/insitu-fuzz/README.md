# Insitu-Fuzz

Insitu-Fuzz is a fuzzing prototype for [Commonware](https://github.com/commonwarexyz/monorepo) that turns existing tests into fuzz targets. It exposes tests with a macro, hooks into runtime and codec internals, and lets AFL++ or LibFuzzer explore input mutations and task scheduling variations against real test logic.

**TL;DR workflow**
1. Run `./setup.sh` to patch the monorepo and generate the registry.
2. Pick a target (fast/all/slow/single-test) and run: `./fuzz.sh --target=fast_tests run` or `./afl.sh --target=fast_tests run`.
3. Reproduce crashes from `fuzz/artifacts/` or `afl/findings/`.

Optional: after monorepo changes, refresh the registry with `bash tools/message_counts.sh --all` and re-run `./setup.sh`.

**Two strategies, two bug classes:**

- **Message mutation**: Corrupts a specific network message inside a real test to stress parsing and validation paths.
- **Task order**: Permutes deterministic runtime scheduling to surface race conditions and ordering assumptions.


See [TECHNICAL.md](TECHNICAL.md) for more information

## Fuzz Targets

### LibFuzzer Targets (fuzz.sh)

**Message mutation**

| Target | Description |
|--------|-------------|
| `fast_tests` | Tests <100ms (default) |
| `all_tests` | All fuzzable tests (see `src/test_registry.rs`) |
| `slow_tests` | Tests >=100ms |
| `simplex` | Single test: consensus simplex |

**Task order**

| Target | Description |
|--------|-------------|
| `task_order_fast_tests` | Task scheduling fuzzing (<100ms tests) |
| `task_order_aggregate` | Single test: consensus aggregation |
| `task_order_simplex` | Single test: consensus simplex |

### AFL++ Targets (afl.sh)

**Message mutation**

| Target | Description |
|--------|-------------|
| `fast_tests` | Tests <100ms (default) |
| `all_tests` | All fuzzable tests (see `src/test_registry.rs`) |
| `slow_tests` | Tests >=100ms |
| `single_range` | Single test with deferred fork (requires TEST_IDX, MSG_IDX) |
| `reshare_restart` | Reshare restart test (134k msgs, requires MSG_IDX) |
| `broadcast_get_cached` | Single test: broadcast get_cached |

**Task order**

| Target | Description |
|--------|-------------|
| `task_order_fast_tests` | Task scheduling fuzzing (<100ms tests) |
| `task_order_aggregate` | Single test: consensus aggregation |
| `task_order_simplex` | Single test: consensus simplex |
| `task_order_reshare` | Reshare with many forced failures (deferred fork, MSG_IDX) |

## Usage

### LibFuzzer (fuzz.sh)
```bash
./fuzz.sh run
./fuzz.sh --target=all_tests run
./fuzz.sh --target=slow_tests run
./fuzz.sh --target=simplex run
```

### AFL++ (afl.sh)
```bash
./afl.sh run
./afl.sh --target=all_tests run
./afl.sh --target=broadcast_get_cached run
MSG_IDX=1000 ./afl.sh --target=reshare_restart run
TEST_IDX=40 MSG_IDX=100 ./afl.sh --target=single_range run
MSG_IDX=1000 ./afl.sh --target=task_order_reshare run
```

## Interpreting Results

Crash artifacts:
- LibFuzzer: `fuzz/artifacts/<target>/`
- AFL++: `afl/findings/<target>/crashes/`

Reproduce:
```bash
./fuzz.sh --target=<target> run fuzz/artifacts/<target>/crash-<hash>
```

What crashes mean:
- Message mutation: production code panicked on malformed input (test/infra panics are filtered).
- Task order: any panic indicates ordering bugs.

## Fuzzing Input Formats (Short)

Message mutation:
```
[msg_idx: u16 LE][xor_key...]                    # single-test targets
[test_selector: u16 LE][msg_idx: u16 LE][xor_key...]  # multi-test targets
```

Task order:
```
[task_order_bytes...]                            # single-test targets
[test_selector: u16 LE][task_order_bytes...]     # multi-test targets
```

## Panic Filtering (Test Oracle)

Insitu-Fuzz builds a test-oracle map of test code ranges at compile time and
filters panics from test and infrastructure code. Panics originating in
production code abort and are reported as findings.

## How It Works (Short Version)

- `tools/message_counts.sh` runs Commonware tests with `MSG_INFO=1` and generates `tools/message_counts.json`.
- `scripts/patch_tests.sh` applies bulk edits, adds `#[fuzzable_test]`, and generates `src/test_registry.rs`.
- `setup.sh` orchestrates patches and registry generation.
- Runtime and codec hooks are weak-linked so `insitu-fuzz` can override them at link time:
  - message corruption hook in `p2p` codec
  - task permutation hook in deterministic runtime
  - AFL deferred-fork checkpoint

For the full pipeline and script details, see `TECHNICAL.md`.

## Tests

```bash
./fuzz.sh test
./afl.sh test
```

`fuzzer_test` includes unit tests for corruption mechanics and integration tests
that run real Commonware tests through the hooks.

## Requirements

- Rust nightly
- cargo-fuzz (LibFuzzer)
- cargo-afl (AFL++)
- cargo-nextest
- python3
- bash, jq
