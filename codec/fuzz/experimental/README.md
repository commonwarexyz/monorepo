# commonware-codec experimental tests

Tests and proof harnesses for the `commonware-codec` crate that are not
libFuzzer targets. They are run by hand or by a scheduled job, not by CI.

## Layout

`codec/fuzz/experimental/` is a plain directory. The parent `codec/fuzz/` is the
`commonware-codec-fuzz` package with the codec fuzz targets.

| Package | Crate | Contents |
| ------- | ----- | -------- |
| [`ephyra/`](./ephyra) | `commonware-codec-fuzz-ephyra` | Five property tests of documented contracts, written with the [ephyra](https://github.com/datadog-labs/ephyra) library. Tests only: no library and no fuzz targets. |
| [`kani/`](./kani) | `commonware-codec-fuzz-kani` | 24 proof harnesses of documented contracts, checked with the [Kani](https://github.com/model-checking/kani) model checker. Harnesses only: nothing is compiled outside `cargo kani`, and there are no fuzz targets. See [its README](./kani/README.md). |

`ephyra` is its own workspace with its own `Cargo.lock`. It is not a member of
the repository workspace, so `cargo` commands run for the repository workspace
do not build or run it, and the repository `Cargo.lock` does not name its
dependencies. The `ephyra` library is pinned to one commit in
`ephyra/Cargo.toml`.

`kani` is its own workspace with its own `Cargo.lock` in the same way. Kani
is a tool and not a dependency: `kani/Cargo.toml` names the Kani release the
harnesses are written for.

## How ephyra tests are marked

Three marks agree, so that a person or a script can find the ephyra tests and
run them without any libFuzzer target:

1. **The path and the package name.** The package is
   `<crate>/fuzz/experimental/ephyra/` and its name ends with `-ephyra`.
2. **A marker in the manifest.** `Cargo.toml` has the table
   `[package.metadata.ephyra]`, with the pinned ephyra commit as `rev`. A
   libFuzzer package has `cargo-fuzz = true` instead, and never this table.
3. **The test names.** The name of every property test starts with `ephyra_`.

Find every ephyra package, from the repository root. The search looks only at
`<crate>/fuzz/experimental/ephyra/Cargo.toml`, where `<crate>` is one or two
folders below the root (`codec`, `cryptography/curve25519`). A copy of a
package in a deeper folder is not found:

```bash
find . -mindepth 5 -maxdepth 6 -path '*/fuzz/experimental/ephyra/Cargo.toml' \
    -exec grep -l '^\[package\.metadata\.ephyra\]' {} +
```

List the property tests of this one:

```bash
cargo test --locked --manifest-path codec/fuzz/experimental/ephyra/Cargo.toml -- --list | grep '^ephyra_'
```

## How Kani proofs are marked

The same three marks, so that a person or a script can find the Kani
harnesses and run them without any libFuzzer target and without any ephyra
test:

1. **The path and the package name.** The package is
   `<crate>/fuzz/experimental/kani/` and its name ends with `-kani`.
2. **A marker in the manifest.** `Cargo.toml` has the table
   `[package.metadata.kani]`, with the Kani release as `version` and the
   number of harnesses as `harnesses`. A libFuzzer package has
   `cargo-fuzz = true` instead, and never this table.
3. **The harness names.** The name of every harness starts with `kani_`.

Find every Kani package, from the repository root. The search looks only at
`<crate>/fuzz/experimental/kani/Cargo.toml`, where `<crate>` is one or two
folders below the root (`codec`, `cryptography/curve25519`). A copy of a
package in a deeper folder is not found:

```bash
find . -mindepth 5 -maxdepth 6 -path '*/fuzz/experimental/kani/Cargo.toml' \
    -exec grep -l '^\[package\.metadata\.kani\]' {} +
```

List the harnesses of this one, and run them:

```bash
cargo kani --manifest-path codec/fuzz/experimental/kani/Cargo.toml list
cargo kani --manifest-path codec/fuzz/experimental/kani/Cargo.toml -j 4 --output-format terse
```

How to install Kani, what a passing run looks like and what each harness
proves are in [`kani/README.md`](./kani/README.md). The rest of this page is
about the ephyra tests.

## Properties

Each property checks contracts that the documentation of `commonware-codec`
states. The quoted sentences, and what is left unasserted, are in the comments
above each property in `ephyra/tests/properties/main.rs`.

| Property | What it checks |
| -------- | -------------- |
| `ephyra_p1_integer_encodings_match_reference_models` | varints, ZigZag, `usize` and `Uint` against reference models |
| `ephyra_p2_roundtrip_exact_size_full_consumption` | `decode(encode(x)) == x`, `encode_size`, `ExtraData`, `write_bufs`, `Modes` |
| `ephyra_p3_length_limits_are_enforced` | `RangeCfg` limits and `InvalidLength` |
| `ephyra_p4_untrusted_bytes_never_panic_and_accepted_values_roundtrip` | edited and forged inputs: no panic, the same answer from every input adapter, accepted values round trip |
| `ephyra_p5_declared_sizes_are_honoured` | `FixedSize::SIZE`, `MAX_ENCODE_SIZE`, `max_items_size` |

## Running

Run from the repository root and pass the manifest. The filter `ephyra_` runs
the five properties and nothing else:

```bash
cargo test --locked --manifest-path codec/fuzz/experimental/ephyra/Cargo.toml ephyra_
```

Without settings the run is deterministic: a fixed seed and 1,000 cases per
property, about one second in total. Without the filter the same command also
runs two generator checks and the test of the `Chunks` adapter (see "Unsafe
code and Miri").

### Budget and seed

The settings come from the environment, with no rebuild:

| Variable | Effect |
| -------- | ------ |
| `EPHYRA_SEED` | The seed. The default seed repeats the same cases, so give a new seed to a longer run. |
| `EPHYRA_TESTS` | Passing cases per property. |
| `EPHYRA_BUDGET_MS` | Stop each property after this many milliseconds, if `EPHYRA_TESTS` is not reached first. |
| `EPHYRA_REPORT_JSON` | Append one JSON report per property to this file. Give an absolute path. |
| `EPHYRA_REGRESSIONS=1` | Save failing inputs and replay them first on the next run (folder: `EPHYRA_REGRESSIONS_DIR`). Off by default. |
| `EPHYRA_REPLAY=seed:iteration` | Test one input first. A failure report prints this line. |

A long run with a time budget, here ten minutes per property, one property
after another. The release profile of this package keeps debug assertions and
overflow checks on:

```bash
EPHYRA_SEED=$(date +%s) EPHYRA_TESTS=4000000000 EPHYRA_BUDGET_MS=600000 \
EPHYRA_REPORT_JSON="$PWD/properties.jsonl" \
cargo test --release --locked --manifest-path codec/fuzz/experimental/ephyra/Cargo.toml \
    ephyra_ -- --skip checks:: --test-threads=1
```

### Generator checks

`ephyra/tests/properties/checks.rs` checks the generators behind the
properties: the generated values, the shrink candidates and the mutants stay
inside each generator's support. Two of the checks run with an unfiltered
`cargo test`. The rest are ignored tests, 10,000 inputs each:

```bash
cargo test --release --locked --manifest-path codec/fuzz/experimental/ephyra/Cargo.toml \
    -- checks:: --include-ignored
```

### Unsafe code and Miri

`ephyra/tests/properties/main.rs` has one piece of unsafe code: `Chunks`, a
`BufMut` that counts the bytes written inline. Its test is in the `miri` test
group, so its name ends with `_miri_`. The repository recipe `just miri`
selects packages of the repository workspace, so run Miri with the manifest.
Use the nightly that the repository pins for its tooling: the first line reads
it from `nightly` under `[tools]` in
[`.github/toolchains.toml`](../../../.github/toolchains.toml), as `just miri`
does. Run from the repository root:

```bash
NIGHTLY=$(sed -n 's/^nightly = "\(.*\)"/\1/p' .github/toolchains.toml)
MIRIFLAGS="-Zmiri-disable-isolation" cargo "+$NIGHTLY" miri test --locked \
    --manifest-path codec/fuzz/experimental/ephyra/Cargo.toml _miri_
```

### The lock file

`ephyra/Cargo.lock` also records the repository crates that the tests depend
on. When their versions or dependencies change, `--locked` fails until the lock
is refreshed and committed:

```bash
cargo metadata --manifest-path codec/fuzz/experimental/ephyra/Cargo.toml --format-version 1 > /dev/null
```
