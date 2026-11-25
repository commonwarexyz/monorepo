# commonware-storage Kani proofs

Proof harnesses for the `commonware-storage` crate, checked with
[Kani](https://github.com/model-checking/kani), a bounded model checker for Rust. A harness
that passes holds for every input inside its stated bounds, not for a sample. The harnesses
are run by hand or by a scheduled job, not by CI.

The harnesses call only the public API of `commonware-storage`: the position and location
math of the Merkle families (MMR and MMB), and the synchronous public items of the contiguous
journal. Private code is not reached; what that leaves out is listed under "Not covered".

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
RUSTFLAGS="--cap-lints=warn" cargo kani --manifest-path storage/fuzz/experimental/kani/Cargo.toml list
```

## Installing Kani

Kani is not a dependency of the repository. The harnesses are written for Kani 0.68.0 (the
`version` of the marker):

```bash
cargo install --locked kani-verifier --version 0.68.0
cargo kani setup
```

## Running

Run from the repository root and pass the manifest:

```bash
RUSTFLAGS="--cap-lints=warn" cargo kani --manifest-path storage/fuzz/experimental/kani/Cargo.toml
```

`RUSTFLAGS="--cap-lints=warn"` is required. The repository denies warnings, and under Kani's
compiler `commonware-utils`, a dependency of `commonware-storage`, gets the lint
`semicolon_in_expressions_from_non_local_macros` (Kani's standard library defines its own
`assert!`), so the build fails without it. The flag only turns lints into warnings; it does
not change what Kani checks.

A full run, one harness at a time, took about 61 minutes of verification time on a 16-core
laptop (2026-11-24). Five harnesses take over 5 minutes each: the peaks proofs (9 and 17
minutes, about 8 GB of memory each), `kani_p2_mmb_valid_size_agrees` (8 minutes, 3 GB) and the
two `kani_p1_*_try_from` proofs (6 minutes each). The two `kani_p1_*_try_from_leaf` proofs take
4 minutes; the others take under 2 minutes and under 2 GB.
`-j 4 --output-format terse` runs four harnesses at a time and prints less; the memory of the
harnesses running at once adds up.

A passing run exits with status 0 and ends with:

```text
Complete - 21 successfully verified harnesses, 0 failures, 21 total.
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
| `--harness kani_p3_mmb_peaks` | Run the harnesses whose name contains this text. |
| `-Z unstable-options --harness-timeout 20m` | Stop each harness after this time. |
| `-Z concrete-playback --concrete-playback=print` | Print a unit test with the input of each failed check and of each satisfied cover check. |
| `--features consistency` | Also assert the implementation-consistency checks (see below). |

Kani has no `--locked` option. Check the lock file before a run with
`cargo metadata --locked --manifest-path storage/fuzz/experimental/kani/Cargo.toml`.

## Proofs

Each proof states contracts that the documentation of `commonware-storage` gives or, where the
documentation is silent, that a test of `commonware-storage` asserts. The quoted sentences, the
bounds and what is left unasserted are in the header of each module in `src/`.

| Module | Harnesses | What is proven |
| ------ | --------- | -------------- |
| `p1_location_position` | `kani_p1_{mmr,mmb}_location_roundtrip`, `kani_p1_{mmr,mmb}_position_to_location_sound`, `kani_p1_{mmr,mmb}_try_from`, `kani_p1_{mmr,mmb}_try_from_leaf`, `kani_p1_mmb_refine_loop_bound` | For every leaf count up to `MAX_LEAVES`, `location_to_position` gives a size up to `MAX_NODES` that `position_to_location` maps back. For every position up to `MAX_NODES`, a returned location maps back to the position. Together: `position_to_location` returns `Some(n)` exactly for the size of `n` leaves. For every `u64`, both `TryFrom` conversions agree with that and return an error otherwise (`LocationOverflow` for `Position::try_from`; the exact kinds and payloads only with `--features consistency`); every size of a valid leaf count converts back (MMR `Location::try_from`: positions and leaf counts below 2^16, and the `MAX_NODES` and `MAX_LEAVES` boundaries). With `--features consistency`: the MMB refinement loop runs its body at most twice for every leaf position. |
| `p2_sizes` | `kani_p2_{mmr,mmb}_valid_size_agrees`, `kani_p2_{mmr,mmb}_to_nearest_size` | `is_valid_size` agrees with `position_to_location` and is false above `MAX_NODES`. `to_nearest_size` returns a valid size no greater than its input, and every valid size up to the input is up to the result. MMR: sizes below 2^16; MMB: every size. |
| `p3_peaks` | `kani_p3_{mmr,mmb}_peaks` | For every leaf count below 2^10 (MMR) or 2^12 (MMB): at most 64 peaks (exactly `ilog2(n + 1)` for the MMB), heights strictly decreasing (MMR) or non-increasing (MMB), each peak inside the structure, of its listed height and at the root of the aligned subtree that follows the previous peak; the peaks cover exactly the leaves and their trees hold exactly the nodes. `inactive_peaks` counts the oldest peaks whose leaves all precede the floor, for every valid floor (up to `MAX_LEAVES`). |
| `p4_nodes` | `kani_p4_{mmr,mmb}_append_schedule`, `kani_p4_{mmr,mmb}_children` | The nodes created when a leaf is appended are the leaf and one parent per height of `parent_heights`, each with that height, an aligned leftmost leaf given by `birth_offset`, and the position `subtree_root_position` gives (MMR: leaf counts below 2^12; MMB: below 2^32). For every height and every aligned leftmost leaf of a node that exists in a valid structure, the node has that height, `leftmost_leaf` gives the leaf back, and its children are the nodes over the two halves of its leaves (MMR: leftmost leaves below 2^16, heights up to 16; MMB: every height up to 61, whole domain). |
| `p5_journal` | `kani_p5_batch_into_iter`, `kani_p5_many_len` | `Batch::into_iter` yields `(start + i, items[i])` for each item and nothing more, for every start inside the documented precondition (up to 3 items). `Many::len` is the total item count and `is_empty` is true exactly when it is zero (`Flat` up to 4 items, `Nested` up to 3 slices of up to 2 items). |

### Contract and consistency

The default build asserts the quoted contracts. It is the gate: a failure is a difference
between the code and a quoted contract. Where the documentation is silent, an item rests on a
test of `commonware-storage`, and the module header says so: the append schedule that ties
`parent_heights`, `birth_offset`, `subtree_root_position` and `pos_to_height` together. A test
supports what it asserts and no more: the payloads of the `TryFrom` errors and the exact error
kinds of `Location::try_from`, which tests assert only for a few inputs, are consistency checks.
The documented `LocationOverflow` kind of `Position::try_from` stays in the gate. Citations
name the file and the item (type, trait method or test) with the quoted text, not line numbers.

Some harnesses also hold checks that are stronger than the documentation. They are asserted
only with `--features consistency`. A valid change of the implementation may fail them, so a
failure there is a reason to look, not a defect.

### Unwind bounds

Kani unrolls each loop up to the bound of `#[kani::unwind(n)]` and fails the proof with an
unwinding assertion if a loop could run longer. For a loop that leaves through a `return`
inside its body, as the MMB refinement loop does, `#[kani::unwind(n)]` passes exactly when the
body runs at most `n` times. This was measured with Kani 0.68.0 on a loop whose body runs 1 to
`m` times: `n = m` and `n = m + 1` passed, `n = m - 1` failed with "unwinding assertion loop
0", for `m` of 2 and 3. So `kani_p1_mmb_refine_loop_bound`, built with `--features consistency`
and then run with `#[kani::unwind(2)]`, proves "the loop body runs at most twice". That sentence
is a comment in the body of the MMB `position_to_location`, not documentation, so the check is a
consistency check; in the default build the harness runs at unwind 4.

### Limits

- A proof holds inside its bounds: the input ranges and loop bounds in the module header.
- `usize` is 64 bits, as on the machine that runs Kani. Nothing here speaks for 32-bit
  targets.
- The MMR proofs of `is_valid_size`, `to_nearest_size`, the peaks, the append schedule and
  `children` are bounded (sizes or leftmost leaves below 2^16, leaf counts below 2^10 or
  2^12): their loops walk the bits of the size, and over the full domain the solver gave no
  answer in reasonable time. The MMR `Location::try_from` proofs are bounded below 2^16 (plus
  the boundaries): building its `Result` over the large error enum made them slow. The MMB
  peaks are bounded below 2^12.
- A proof is as sound as Kani, CBMC and the solver.

## Not covered

These properties need private code, a panic proof method the nightly runner does not have, or
asynchronous code. They are left out on purpose.

| What | Why it is left out |
| ---- | ------------------ |
| Journal section and offset math: `batch_count_to_blob_boundary`, `position_to_blob`, `blob_first_position`, `blob_end_position` (`storage/src/journal/contiguous/mod.rs`), `first_in_blob` and `items_to_bytes` (`storage/src/journal/contiguous/fixed.rs`), `decode_length_prefix` and `find_frame` (`storage/src/journal/frame.rs`) | Private or `pub(super)`. Only the public API is used (decision, 2026-11-24): reaching them needs a proof module inside the production file or a hash-checked copy of the functions. The journal types that use them are built only by an asynchronous `init` on a runtime, which Kani does not run. |
| Panics on invalid input: `to_nearest_size` above `MAX_NODES`, the peak iterators on an invalid size, `nodes_to_pin` above `MAX_LEAVES`, the "height too large" panics of `subtree_root_position`, `leftmost_leaf` and `birth_offset` | A proof that every invalid input panics needs a `#[kani::should_panic]` harness whose cover must be unreachable, with a control harness. The pass rule of the nightly runner (every cover satisfied) would fail such a harness. |
| The MMR `is_valid_size`, `to_nearest_size`, peak walk, append schedule and `children` over the full domain, and the MMR `Location::try_from` between 2^16 and `MAX_NODES` | Cost: the 63-step descent of `is_valid_size` gave no answer within 38 minutes over the full domain and within 17 minutes below 2^32; `children` over every height up to 62 gave none within 20 minutes. The full-domain round trip of `p1` pins `position_to_location` down everywhere (the code of `Location::try_from` calls it, but no documentation says so, so this is not claimed as a proof of `try_from`); the others are proven below 2^16 (leaf counts below 2^10 for the peaks and 2^12 for the append schedule). |
| `nodes_to_pin`, `Graftable::chunk_peaks`, proof planning (`RangePlan`, `multi_proof_positions`), the arithmetic helpers of `Location` and `Position`, and their codec | Not part of this package. |
| 32-bit targets | Kani runs on a 64-bit host. |

## Changing the harnesses

- Name a new harness `kani_...` and raise `harnesses` in `Cargo.toml`.
- Call only the public API of `commonware-storage`.
- Put the quoted contract, with its file and item, in the module header. A check with no quote
  goes behind the `consistency!` macro. A quoted test supports what it asserts and no more.
- Give every result arm a `kani::cover!` check, so that an arm that is no longer reached is
  seen.
- Write the bounds in the module header, and an unwind bound on every harness with a loop.

### The lock file

`Cargo.lock` also records the repository crates that the harnesses depend on. When their
versions or dependencies change, refresh the lock and commit it:

```bash
cargo metadata --manifest-path storage/fuzz/experimental/kani/Cargo.toml --format-version 1 > /dev/null
```
