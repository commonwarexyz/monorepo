# commonware-codec Kani proofs

Proof harnesses for the `commonware-codec` crate, checked with
[Kani](https://github.com/model-checking/kani), a bounded model checker for Rust. A harness
that passes holds for every input inside its stated bounds, not for a sample. The harnesses
are run by hand or by a scheduled job, not by CI.

`kani/` is its own workspace with its own `Cargo.lock`. It is not a member of the repository
workspace, so `cargo` commands run for the repository workspace do not build or run it, and
the repository `Cargo.lock` does not name it. Every module and every dependency is behind
`cfg(kani)`: under a plain `cargo build` the package is empty.

## How Kani harnesses are marked

Three marks agree, so that a person or a script can find the Kani harnesses and run them
without any libFuzzer target:

1. **The path and the package name.** The package is `<crate>/fuzz/experimental/kani/` and
   its name ends with `-kani`.
2. **A marker in the manifest.** `Cargo.toml` has the table `[package.metadata.kani]`, with
   the Kani release as `version` and the number of harnesses as `harnesses`. A libFuzzer
   package has `cargo-fuzz = true` instead, and never this table.
3. **The harness names.** The name of every harness starts with `kani_`.

Find every Kani package, from the repository root. The search looks only at
`<crate>/fuzz/experimental/kani/Cargo.toml`, where `<crate>` is one or two folders below the
root (`codec`, `cryptography/curve25519`). A copy of a package in a deeper folder is not found:

```bash
find . -mindepth 5 -maxdepth 6 -path '*/fuzz/experimental/kani/Cargo.toml' \
    -exec grep -l '^\[package\.metadata\.kani\]' {} +
```

List the harnesses of this one:

```bash
cargo kani --manifest-path codec/fuzz/experimental/kani/Cargo.toml list
```

## Installing Kani

Kani is not a dependency of the repository. The harnesses are written for Kani 0.68.0 (the
`version` of the marker). Both commands install into the home directory: the two binaries in
`~/.cargo/bin`, the Kani bundle in `~/.kani`, and the compiler Kani uses as a `rustup`
toolchain.

```bash
cargo install --locked kani-verifier --version 0.68.0
cargo kani setup
```

## Running

Run from the repository root and pass the manifest:

```bash
cargo kani --manifest-path codec/fuzz/experimental/kani/Cargo.toml -j 4 --output-format terse
```

A passing run exits with status 0 and ends with:

```text
Complete - 24 successfully verified harnesses, 0 failures, 24 total.
```

Check two more things, because the exit status does not cover them:

1. **The count.** The total equals `harnesses` in the marker. A harness that is no longer
   compiled is missing from the run without any error.
2. **The cover checks.** Every line `** n of m cover properties satisfied` has `n` equal to
   `m`. Kani reports a harness as `SUCCESSFUL` also when a cover check is unsatisfied, and
   then the harness may prove less than it says.

A harness that runs out of time is printed as `VERIFICATION:- FAILED` with the line
`CBMC timed out`: that is no answer, not a failed check. A failed check prints
`Failed Checks:` with the assertion.

Useful options:

| Option | Effect |
| ------ | ------ |
| `--harness kani_p4_usize_read` | Run the harnesses whose name contains this text. |
| `-Z unstable-options --harness-timeout 20m` | Stop each harness after this time. |
| `-Z unstable-options --export-json results.json` | Write the result of every harness and every check to a file. |
| `-Z concrete-playback --concrete-playback=print` | Print a unit test with the input of each failed check and of each satisfied cover check. |
| `--features consistency` | Also assert the implementation-consistency checks (see below). |

Kani has no `--locked` option. Check the lock file before a run with
`cargo metadata --locked --manifest-path codec/fuzz/experimental/kani/Cargo.toml`.

## Proofs

Each proof states contracts that the documentation of `commonware-codec` gives. The quoted
sentences, the bounds and what is left unasserted are in the header of each module in `src/`.

| Module | Harnesses | What is proven |
| ------ | --------- | -------------- |
| `p1_varint_decode` | `kani_p1_decode_{u16,u32,u64,u128}`, `kani_p1_max_sizes_match_codec` | For every byte string up to one byte past the longest varint: decoding does not panic, fails only with `EndOfBuffer` or `InvalidVarint`, and accepts only the canonical encoding of the value it returns. |
| `p2_varint_roundtrip` | `kani_p2_roundtrip_{u16,u32,u64,u128,i16,i32,i64,i128}` | For every value of the type: the encoding has the size `encode_size` gives and decoding gives the value back. For unsigned values that size is minimal. Signed values use ZigZag. |
| `p3_stream_decoder` | `kani_p3_stream_{u16,u32,u64,u128}` | For every byte sequence fed to a new decoder: it does not panic, asks for more only after a continuation byte, fails only with `InvalidVarint`, and stops within the longest varint. |
| `p4_range` | `kani_p4_range_contains`, `kani_p4_usize_read` | `RangeCfg::contains` is interval membership for every pair of bounds. For every byte string up to 6 bytes and every range, a decoded `usize` length is inside the caller's range. |
| `p5_length_math` | `kani_p5_at_least_items`, `kani_p5_max_items_size`, `kani_p5_ensure_zeros` | The length check does not overflow, the size bound is an upper bound, and the padding check accepts exactly a zero region. |
| `p6_varint_uint14` | `kani_p6_decode_uint14`, `kani_p6_stream_uint14` | The properties of `p1` and `p3` for a 14-bit `Uint`, a width that is a multiple of 7 bits. |

### Contract and consistency

The default build asserts the quoted contracts. It is the gate: a failure is a difference
between the code and its documented contract. Two items rest on a
comment in the code and not on API documentation; the module headers say which.

Some harnesses also hold checks that are stronger than the documentation, for example the
exact payload of an error. They are asserted only with `--features consistency`. A valid
change of the implementation may fail them, so a failure there is a reason to look, not a
defect.

### Limits

- A proof holds inside its bounds: the input lengths and loop bounds in the module header.
- `usize` is 64 bits, as on the machine that runs Kani. Nothing here speaks for 32-bit
  targets.
- The proofs cover the listed functions on stack data. Heap-backed types (`Vec`, `Bytes`) are
  not covered.
- Which error kinds a function may return is read from the description of each kind in
  `codec/src/error.rs`. The documentation has no list of kinds per function.
- A proof is as sound as Kani, CBMC and the solver.

## Changing the harnesses

- Name a new harness `kani_...` and raise `harnesses` in `Cargo.toml`.
- Put the quoted contract above the assertion. A check with no quote goes behind the
  `consistency!` macro.
- Give every result arm a `kani::cover!` check, so that an arm that is no longer reached is
  seen.

### The lock file

`Cargo.lock` also records the repository crates that the harnesses depend on. When their
versions or dependencies change, refresh the lock and commit it:

```bash
cargo metadata --manifest-path codec/fuzz/experimental/kani/Cargo.toml --format-version 1 > /dev/null
```
