# commonware-coding Kani proofs

Proof harnesses for the `commonware-coding` crate, checked with
[Kani](https://github.com/model-checking/kani), a bounded model checker for Rust. A harness
that passes holds for every input inside its stated bounds, not for a sample. The harnesses
are run by hand or by a scheduled job, not by CI.

The harnesses call only the public API of `commonware-coding`: the `Config` type and the
chunk type of the Reed-Solomon scheme (`<ReedSolomon<Sha256> as Scheme>::Shard`). They do not
call or copy private helpers directly. The public calls run the private code behind them (for
example, decoding a chunk computes the canonical shard width), so that code is checked for the
inputs the harnesses use, but no private helper is proven over its own domain. What that
leaves out is listed under "Not covered".

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

List the harnesses of this package:

```bash
RUSTFLAGS="--cap-lints=warn" cargo kani --manifest-path coding/fuzz/experimental/kani/Cargo.toml list
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
RUSTFLAGS="--cap-lints=warn" cargo kani --manifest-path coding/fuzz/experimental/kani/Cargo.toml
```

`RUSTFLAGS="--cap-lints=warn"` is required. The repository workspace denies warnings, and
under Kani's compiler `commonware-utils`, a dependency of `commonware-coding`, gets a
future-incompatibility warning (Kani's standard library defines its own `assert!`, which then
is not local to the crate). Without the flag the build stops with "trailing semicolon in macro
used in expression position". The flag only turns lints of the code under proof into
warnings; it does not change what Kani checks.

To check one harness, name it with its module and pass `--exact`:

```bash
RUSTFLAGS="--cap-lints=warn" cargo kani --manifest-path coding/fuzz/experimental/kani/Cargo.toml \
    --harness p6_chunk_reencode::kani_chunk_reencode --exact
```

A passing run exits with status 0 and ends with:

```text
Complete - 5 successfully verified harnesses, 0 failures, 5 total.
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
| `-j 1` | Run one harness at a time (each harness runs one solver process). |
| `-Z unstable-options --harness-timeout 5m` | Stop each harness after this time. |
| `-Z unstable-options --export-json results.json` | Write the result of every harness and every check to a file. |
| `-Z concrete-playback --concrete-playback=print` | Print a unit test with the input of each failed check and of each satisfied cover check. |
| `--features consistency` | Also assert the implementation-consistency checks (see below). |

Kani has no `--locked` option. Check the lock file before a run with
`cargo metadata --locked --manifest-path coding/fuzz/experimental/kani/Cargo.toml --format-version 1`.

## Proofs

Each proof states contracts that the documentation of `commonware-coding` gives, or the
documentation of `commonware-codec` and `commonware-storage` whose types it uses; where that
documentation is silent, a test, a code comment or the implementation code (see "Contract and
consistency" below). The quoted sentences, the item each quote belongs to, the bounds and what
is left unasserted are in the header of each module in `src/`. Quotes name the file and the
item, not line numbers.

| Module | Harness | What is proven |
| ------ | ------- | -------------- |
| `p1_config` | `kani_config_decode_roundtrip` | For every 4-byte input: a `Config` decodes exactly when both 2-byte fields are nonzero, takes the two big-endian values, and encodes to the same 4 bytes. |
| `p2_total_shards` | `kani_config_total_shards` | For every `Config`: `total_shards` is `minimum_shards + extra_shards` as a `u32`, without overflow. |
| `p3_config_size` | `kani_config_exact_size` | For every input of 0 to 6 bytes: a `Config` decodes only from exactly 4 bytes. |
| `p4_chunk_size_bound` | `kani_chunk_max_encode_size` | For every chunk of one shape (an 8-byte shard under one minimum shard and a 4-byte maximum, every content, index and leaf count, no sibling digest): if it decodes, its encoded size is at most `Chunk::max_encode_size` of the widest allowed shard and 32 sibling digests. |
| `p6_chunk_reencode` | `kani_chunk_reencode` | For every chunk of the 8-byte shape that decodes: encoding it gives exactly the input bytes. |

### Contract and consistency

The default build asserts the quoted contracts. It is the gate: a failure is a difference
between the code and a quoted source. Where the API documentation is silent, an item rests on
a test, a code comment or the implementation code of `commonware-coding`, `commonware-codec`
or `commonware-storage` (for example the field order of `Config` and of a chunk), and the
module header says which kind. For an item that rests on implementation code, a failure can
also mean that the quoted code changed, not only that a documented contract broke. Some harnesses also hold checks that
are stronger than the documentation, for example that a chunk within the width decodes. They
are asserted only with `--features consistency`. A valid change of the implementation may
fail them, so a failure there is a reason to look, not a defect.

### Limits

- A proof holds inside its bounds: the sizes in the module header.
- `usize` is 64 bits, as on the machine that runs Kani. Nothing here speaks for 32-bit
  targets.
- The chunk proofs use SHA-256 digests and one shape each (see "Not covered").
- A proof is as sound as Kani, CBMC and the solver.

## Not covered

Decision, 2026-11-24: the harnesses use the public API only, with no change to production
code and no copy of private code. These properties need more than that, or did not finish
small enough:

| Property | Why it is not covered |
| -------- | --------------------- |
| Chunks of other shard lengths, other configurations and other maxima | Measured with Kani 0.68.0: a symbolic shard length (a `Bytes` of symbolic size), a symbolic configuration (a division by a symbolic shard count in the width) or several shapes in one harness gave no answer within 3 to 10 minutes. The proofs fix one shape each. |
| Chunks with sibling digests | A symbolic sibling count drove the solver above 12 GB within a minute. |
| That a chunk whose shard is wider than the documented width does not decode | Measured with Kani 0.68.0: a 9-byte shard under a width of 8 (one minimum shard, 4 data bytes) gave no answer within 5 minutes with symbolic content, index and leaf count, within 3 minutes with only the content symbolic, and within 3 minutes for one fully concrete input, although the accepted 8-byte shape finishes in seconds. The decoding fuzz target in `coding/fuzz/` checks this bound. |
| That every chunk within the allowed width decodes | The documentation states only that a wider shard does not decode; the converse is a consistency check, for one shape. |
| The private helpers of the scheme over their own domains: the canonical shard width, the length prefix and padding checks, the shard index and proof checks | Private code. The harnesses reach some of it through the public calls, only for the fixed shapes; the width is checked only through decoding, against a reference written from the documentation. |
| `Scheme::encode`, `check` and `decode`: the Reed-Solomon field arithmetic over the shards, the Merkle tree and the hashing | Too large for a bounded model checker at useful sizes; the arithmetic uses SIMD code. The fuzz targets in `coding/fuzz/` cover them. |

## Changing the harnesses

- Name a new harness `kani_...` and raise `harnesses` in `Cargo.toml`.
- Put the quoted contract above the assertion, with the file and the item it belongs to (no
  line numbers). A check with no quote goes behind the `consistency!` macro. A quoted test
  supports what it asserts and no more.
- Give every result arm a `kani::cover!` check, so that an arm that is no longer reached is
  seen.
- Keep chunk inputs to one concrete shape per harness; check a new harness alone with
  `--harness ... --exact` and a `--harness-timeout`.

### The lock file

`Cargo.lock` also records the repository crates that the harnesses depend on. When their
versions or dependencies change, refresh the lock and commit it:

```bash
cargo metadata --manifest-path coding/fuzz/experimental/kani/Cargo.toml --format-version 1 > /dev/null
```
