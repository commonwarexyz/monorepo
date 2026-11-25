# commonware-utils Kani proofs

Proof harnesses for the `commonware-utils` crate, checked with
[Kani](https://github.com/model-checking/kani), a bounded model checker for Rust. A harness
that passes holds for every input inside its stated bounds, not for a sample. The harnesses
are run by hand or by a scheduled job, not by CI.

`kani/` is its own workspace with its own `Cargo.lock`. It is not a member of the repository
workspace, so `cargo` commands run for the repository workspace do not build or run it, and
the repository `Cargo.lock` does not name it. Every module and every dependency is behind
`cfg(kani)`: under a plain `cargo build` the package is empty.

The harnesses call the public API of `commonware-utils` and `commonware-codec` only. They
copy no private code and need no change to the crates.

## How Kani harnesses are marked

As in `codec/fuzz/experimental/kani/README.md`: the package is
`<crate>/fuzz/experimental/kani/` and its name ends with `-kani`; `Cargo.toml` has the table
`[package.metadata.kani]` with the Kani release as `version` and the number of harnesses as
`harnesses`; the name of every harness starts with `kani_`.

List the harnesses:

```bash
RUSTFLAGS="--cap-lints=warn" cargo kani --manifest-path utils/fuzz/experimental/kani/Cargo.toml list
```

## Installing Kani

The harnesses are written for Kani 0.68.0 (the `version` of the marker):

```bash
cargo install --locked kani-verifier --version 0.68.0
cargo kani setup
```

## Running

Run from the repository root and pass the manifest:

```bash
RUSTFLAGS="--cap-lints=warn" cargo kani --manifest-path utils/fuzz/experimental/kani/Cargo.toml
```

`--cap-lints=warn` is needed: the repository denies warnings, and under Kani's standard
library `commonware-utils` gets a future-incompatibility lint (`assert!` is no longer a
macro local to the crate). The flag lowers lints of the code under proof to warnings; it does
not change what Kani checks.

A passing run exits with status 0 and ends with:

```text
Complete - 16 successfully verified harnesses, 0 failures, 16 total.
```

Check two more things, because the exit status does not cover them:

1. **The count.** The total equals `harnesses` in the marker. A harness that is no longer
   compiled is missing from the run without any error.
2. **The cover checks.** Every line `** n of m cover properties satisfied` has `n` equal to
   `m`. Kani reports a harness as `SUCCESSFUL` also when a cover check is unsatisfied, and
   then the harness may prove less than it says.

Useful options: `--harness <name> --exact` runs one harness; `--features consistency` also
asserts the implementation-consistency checks (see below). Kani has no `--locked` option;
check the lock file first with
`cargo metadata --locked --manifest-path utils/fuzz/experimental/kani/Cargo.toml`.

Memory and time: the two bitmap harnesses build heap values (a `VecDeque`) and are the
expensive ones, about 1 to 2 minutes each and several GB of memory; every other harness
takes seconds. Run one harness at a time (`-j 1`, the default) on a laptop.

## Proofs

Each proof states contracts that the documentation of `commonware-utils` or
`commonware-codec` gives or, where the documentation is silent, that a test of the crate
asserts. The quoted sentences (cited by file and item, never by line), the bounds and what is
left unasserted are in the header of each module in `src/`.

| Module | Harnesses | What is proven |
| ------ | --------- | -------------- |
| `fixed_bytes` | `kani_fixed_bytes_cmp_{16,17,18,19,20,21,22,23,24,63,64,65}` | For every pair of byte arrays of the width, `FixedBytes::cmp` is the lexicographic order of the arrays, the reversed compare is its reverse, and `partial_cmp` agrees. The widths hold both sides of both cutoffs of the word path (16 and 17, 64 and 65) and every remainder modulo 8 inside it. |
| `bitmap` | `kani_bitmap_is_unset`, `kani_bitmap_truncate` | For every 17-bit bitmap (every bit pattern, chunks of 1 byte): `is_unset` is true exactly when no bit of the range is set, for every range; `truncate` to every length from 0 to 17 keeps the length and bits it should and reads the dropped positions as zero after extending back. |
| `prefixed_u64` | `kani_prefixed_u64_new`, `kani_prefixed_u64_decode` | For every prefix and value, `U64::new` keeps both through an encode and a decode. For every input of up to 10 bytes, decoding fails on fewer than 9 bytes and otherwise reads exactly 9, which rebuild the key. |

### Contract and consistency

The default build asserts the quoted contracts. It is the gate: a failure is a difference
between the code and a quoted contract. Some items rest on a test of `commonware-utils`, not
on API documentation: the order of `FixedBytes`, and what `U64::new`, `prefix` and `value`
do. The module headers say which items these are.

Some harnesses also hold checks that are stronger than the documentation, for example the
byte layout of `U64`. They are asserted only with `--features consistency`. A valid change of
the implementation may fail them, so a failure there is a reason to look, not a defect.

### Not covered

- **Decoding a bitmap** (`Read for BitMap`, chunks of 1 and 2 bytes) and **decoding a
  `Prunable`** (`Read for Prunable`, the pruned-count and total-length overflow checks). A
  proof of each was written: a model of the documented rules (the length prefix, the range,
  a missing payload, set bits past the length, the two overflow errors) checked for every
  input and range. On Kani 0.68 the solver used more than 40 GB of memory for each of them,
  also with one chunk of payload, a fixed input length and the range kept symbolic, so they
  were taken out. The decoders keep their fuzz targets and the crate's tests.
- `BitMap::is_unset` past the length and `BitMap::truncate` to a larger length are documented
  to panic. A harness that expects a panic needs a pass rule the scheduled run does not have
  yet.
- `FixedBytes` widths other than the twelve listed: they share a path and a remainder with a
  proven width, which is an argument, not a proof.
- Bitmaps of other lengths than 17 bits, and chunk sizes other than `N = 1`.
- Private helpers of the bitmaps (`clear_trailing_bits` and the chunk arithmetic) are proven
  only through the public functions above: the harnesses use the public API only.

### Limits

- A proof holds inside its bounds: the input lengths and loop bounds in the module header.
- `usize` is 64 bits, as on the machine that runs Kani. Nothing here speaks for 32-bit
  targets.
- A generic implementation is proven for the widths and chunk sizes it is listed with.
- A proof is as sound as Kani, CBMC and the solver.

## Changing the harnesses

- Name a new harness `kani_...` and raise `harnesses` in `Cargo.toml`.
- Put the quoted contract above the assertion, cited by file and item, never by line. A
  check with no quote goes behind the `consistency!` macro. A quoted test supports what it
  asserts and no more.
- Give every result arm a `kani::cover!` check, so that an arm that is no longer reached is
  seen.

### The lock file

`Cargo.lock` also records the repository crates that the harnesses depend on. When their
versions or dependencies change, refresh the lock and commit it:

```bash
cargo metadata --manifest-path utils/fuzz/experimental/kani/Cargo.toml --format-version 1 > /dev/null
```
