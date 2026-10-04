# The shipped verified code against the original Commonware functions

Written by `sandblaster/bench/shipped-harness/run.sh` (report.py); every number below comes from
that run's result files (`sandblaster/bench/shipped-harness/results/`). Finish-A, task 4: the code
commonware-codec and commonware-storage actually compile from sandblaster's emitted and lowered
copies, timed against the original Commonware functions, in one binary, with an A/A control and the
machine-code identity check.

## Headline

**The shipped code is the original code.** In every binary all 33 measured functions
compiled to the same instructions in the shipped subject as in the original one (the identity
check, following calls into each subject's own copies of the two crates): 28 of 33 identical outright, and the other 5 (`hasher_leaf_digest`, `hasher_node_digest`, `mmr_location_from_position`, `mmr_position_from_location`, `proof_verify_element_inclusion`) identical except for the
addresses of the constant data each copy carries (a jump table, SHA-256's initial state: `samecode.py
--data-blind`); the A/A pair, the same source compiled twice, differs in exactly the same way.
Neither check compares the panic messages' constants: each copy has its own, and a panic in
storage's MMR iterator names the file rustc compiled, the lowered copy, two lines further down
than the source (its header replaces the three `//!` lines). That is what the sandblaster build
ships today: codec's varint module is emitted `VERIFIED + LIFTED AS-IS` (a header of comments, then
the original file byte for byte, then rustc-checked host facts that compile to no code), and
storage's MMR iterator is compiled through a lowered copy that is the source byte for byte after
its header (the optimizer found nothing cheaper in either module; the verifier's files, a
development build, are compiled as written). So every timing difference below is code placement
and machine noise, and the A/A row shows its size.

| binary | geomean shipped / original, all functions | geomean A/A / original | A/A spread (per function) | identical code, shipped = original (A/A) | identical except data addresses (A/A) | load before → after |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| default-release | 1.003 | 1.000 | 0.881–1.058 | 28 of 33 (28) | 33 of 33 (33) | 9.69 9.49 8.84 → 7.00 8.61 8.57 |
| align-release | 1.002 | 1.001 | 0.976–1.030 | 28 of 33 (28) | 33 of 33 (33) | 7.70 8.10 8.42 → 13.22 9.77 9.02 |
| default-release-nooc | 1.008 | 0.998 | 0.742–1.161 | 28 of 33 (28) | 33 of 33 (33) | 7.82 11.24 11.48 → 8.60 10.94 11.36 |

Per set (default layout, overflow checks on):

| set | functions | geomean shipped / original | geomean A/A / original | identical code | identical except data addresses |
| --- | ---: | ---: | ---: | ---: | ---: |
| codec's varint (`codec/sandblaster/varint`, module mode: the emitted `varint.rs`) | 20 | 1.007 | 1.007 | 20 of 20 | 20 of 20 |
| storage's MMR position and peak arithmetic (`storage/sandblaster/mmr`, in place: `iterator.rs` through its lowered copy) | 10 | 0.997 | 0.988 | 8 of 10 | 10 of 10 |
| storage's Merkle proof verifier, first set (`storage/sandblaster/verifier`, in place: hasher and proof files compiled as written) | 3 | 1.002 | 0.997 | 0 of 3 | 3 of 3 |

## Every function

Ratios are shipped / original time (< 1: the shipped code is faster); `=` marks a function whose
shipped and original subjects compiled to the same machine code in that binary, `≈` one whose code
is the same except for the addresses of each copy's own constant data (`--data-blind`). A/A /
original is the control: the original code compiled a second time from its own copies.

| set | function | shipped / original [default-release] | shipped / original [align-release] | shipped / original [default-release-nooc] | A/A / original [default-release] | A/A / original [align-release] | A/A / original [default-release-nooc] | rounds p10–p90 [default-release] |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| varint | `varint_u16_write` | = 0.995 | = 1.013 | = 0.997 | 1.000 | 1.009 | 1.002 | 0.989–1.007 |
| varint | `varint_u16_read` | = 0.995 | = 0.996 | = 0.983 | 0.991 | 0.993 | 0.980 | 0.985–0.999 |
| varint | `varint_u16_size` | = 0.994 | = 1.000 | = 1.002 | 1.007 | 1.001 | 1.007 | 0.971–1.008 |
| varint | `varint_u32_write` | = 1.015 | = 0.999 | = 0.999 | 1.022 | 1.000 | 1.003 | 0.979–1.034 |
| varint | `varint_u32_read` | = 1.013 | = 0.997 | = 1.086 | 1.015 | 1.007 | 0.985 | 0.987–1.051 |
| varint | `varint_u32_size` | = 1.000 | = 0.999 | = 1.000 | 1.000 | 1.000 | 1.000 | 0.994–1.001 |
| varint | `varint_u64_write` | = 1.001 | = 1.001 | = 1.004 | 1.002 | 1.001 | 1.001 | 0.991–1.015 |
| varint | `varint_u64_read` | = 1.007 | = 0.996 | = 1.029 | 1.035 | 0.995 | 1.025 | 1.002–1.045 |
| varint | `varint_u64_size` | = 1.000 | = 1.001 | = 1.000 | 1.001 | 1.000 | 1.001 | 0.970–1.018 |
| varint | `varint_i16_write` | = 1.014 | = 1.006 | = 0.999 | 1.025 | 1.004 | 0.997 | 0.981–1.052 |
| varint | `varint_i16_read` | = 0.983 | = 0.995 | = 0.985 | 1.000 | 0.996 | 0.983 | 0.971–0.996 |
| varint | `varint_i16_size` | = 1.000 | = 1.022 | = 1.000 | 1.000 | 1.030 | 1.000 | 1.000–1.000 |
| varint | `varint_i32_write` | = 1.001 | = 1.006 | = 1.015 | 1.001 | 1.000 | 1.011 | 0.984–1.012 |
| varint | `varint_i32_read` | = 1.097 | = 1.009 | = 0.997 | 1.003 | 1.008 | 0.987 | 1.090–1.113 |
| varint | `varint_i32_size` | = 1.000 | = 1.000 | = 1.020 | 1.000 | 0.999 | 1.001 | 1.000–1.000 |
| varint | `varint_i64_write` | = 1.006 | = 1.000 | = 0.997 | 1.009 | 1.001 | 1.000 | 0.995–1.010 |
| varint | `varint_i64_read` | = 1.007 | = 1.000 | = 0.990 | 1.003 | 1.000 | 0.971 | 1.003–1.013 |
| varint | `varint_i64_size` | = 1.019 | = 0.998 | = 0.999 | 1.000 | 0.998 | 0.998 | 0.993–1.020 |
| varint | `varint_u64_decoder` | = 0.992 | = 1.011 | = 0.993 | 1.008 | 1.000 | 0.990 | 0.988–1.001 |
| varint | `varint_u32_decoder` | = 1.000 | = 1.009 | = 1.013 | 1.023 | 1.004 | 1.004 | 0.990–1.007 |
| mmr | `mmr_is_valid_size` | = 1.004 | = 1.005 | = 1.006 | 0.993 | 1.007 | 1.029 | 0.977–1.017 |
| mmr | `mmr_to_nearest_size` | = 1.003 | = 1.026 | = 1.038 | 1.030 | 1.011 | 1.040 | 0.994–1.007 |
| mmr | `mmr_location_to_position` | = 0.999 | = 1.000 | = 0.997 | 0.997 | 1.001 | 0.742 | 0.997–1.012 |
| mmr | `mmr_position_to_location` | = 1.157 | = 0.972 | = 0.981 | 1.031 | 0.976 | 0.985 | 1.107–1.189 |
| mmr | `mmr_peaks` | = 0.903 | = 1.002 | = 1.029 | 0.881 | 1.004 | 1.161 | 0.844–1.181 |
| mmr | `mmr_peak_iterator` | = 0.942 | = 1.008 | = 1.031 | 0.955 | 1.000 | 1.081 | 0.892–1.034 |
| mmr | `mmr_children` | = 1.001 | = 0.999 | = 0.999 | 1.002 | 1.000 | 1.000 | 0.993–1.028 |
| mmr | `mmr_parent_heights` | = 1.007 | = 0.998 | = 0.994 | 1.046 | 0.993 | 0.990 | 1.007–1.030 |
| mmr | `mmr_location_from_position` | ≈ 0.992 | ≈ 1.024 | ≈ 1.066 | 1.058 | 0.992 | 1.035 | 0.953–1.006 |
| mmr | `mmr_position_from_location` | ≈ 0.980 | ≈ 1.000 | ≈ 0.999 | 0.902 | 1.001 | 1.006 | 0.953–0.981 |
| verifier | `hasher_leaf_digest` | ≈ 1.001 | ≈ 1.000 | ≈ 1.003 | 1.001 | 1.001 | 1.003 | 0.997–1.005 |
| verifier | `hasher_node_digest` | ≈ 0.996 | ≈ 0.987 | ≈ 1.000 | 0.996 | 1.002 | 0.980 | 0.980–1.040 |
| verifier | `proof_verify_element_inclusion` | ≈ 1.008 | ≈ 0.994 | ≈ 1.014 | 0.994 | 0.985 | 0.992 | 0.985–1.025 |

A/A pairs identical by the check: 28 of 33 [default-release], 28 of 33 [align-release], 28 of 33 [default-release-nooc].

## What was run

- **Subjects** (one crate source, `subject/lib.rs` with `probe.rs`, over each subject's own copies of
  the two crates, written by `prepare.py` into `gen/`):
  - `original`: commonware-codec and commonware-storage at `960c27ac03c7`, the merge base of the sandblaster
    branch with Commonware's `main` (`git archive`, read-only): the code before sandblaster;
  - `A/A`: the same again, from its own copies: the noise floor;
  - `shipped`: the two crates as this worktree builds them, with the files a verified build writes to
    `OUT_DIR` included where the crates include them (codec's `src/varint.rs` includes the emitted
    `varint.rs`; storage's `src/merkle/mmr/mod.rs` declares `iterator` by its lowered declaration and
    includes `mmr-lowered__merkle__mmr__iterator.rs`); only the include paths differ, so rustc compiles
    the text the host build compiles. The OUT_DIR files and their SHA-256:

```text
base 960c27ac03c79b604ea6a75e7ecf819c37e9296a
shipped codec src/varint.rs <- OUT_DIR/varint.rs sha256 fb796f89d121e27cd11dd8e483a85cc21f4dcbf923ccf4c7f335670d2243d80f
shipped storage src/merkle/mmr/mod.rs <- OUT_DIR/mmr-lowered__merkle__mmr__iterator.rs sha256 25f96c42a3807cc4d2d3d5ad373e69df1d79feda40f05791b22122d509c4f683
orig codec src/varint.rs sha256 47e60874f62bcd6f19fe0d3f8fabda94b8aa9d4849a15b0247cf07763bcb0512
orig storage src/merkle/mmr/iterator.rs sha256 6330eaf101252b2245871d2316d7df35d8d4c995fabe892ad70c77f0c0d55731
```

  Every storage copy links the monorepo's own commonware-codec, as every other crate in its graph does
  (cryptography's types implement that codec's traits): the varint rows time the codec copies, the MMR
  and verifier rows the storage copies.
- **Functions**: the verified functions of the three modules, through their public API (`probe.rs`):
  varint's `UInt`/`SInt` write, read and encoded size at the verified instances (`u16`, `u32`, `u64`,
  `i16`, `i32`, `i64`; the `u128`/`i128` instances are declared unverified; a byte slice is read
  through codec's `Copying` adapter, as codec requires) and `Decoder::feed`; the
  MMR's `Family` methods (`is_valid_size`, `to_nearest_size`, `location_to_position`,
  `position_to_location`, `peaks`, `children`, `parent_heights`), `PeakIterator` and the
  `Position`/`Location` conversions; the verifier's `Standard<Sha256>` leaf and node digests and
  `Proof::verify_element_inclusion` (whose core is the verified `Subtree::reconstruct_digest`) on a
  1024-leaf MMR each subject builds with its own code before timing.
- **Protocol** (the held-out harness's, J11): one workspace profile for all three subjects: rustc -O
  (opt-level 3), 16 codegen units, no LTO, no target-cpu flag, no PGO; overflow checks on (Commonware's
  release profile) and, as a second binary, off; a third binary with every function and block aligned
  to 64 bytes; build scripts optimized, the monorepo's own `build-override` (the one build script is
  the monorepo's commonware-codec's, which every subject's storage copy shares: it compiles no subject
  code). `fair-baseline.sh --heldout` is written for the held-out harness's subjects (`subj_rustc`, ..)
  and refuses any `build-override`, so it does not apply here as it stands; the rest of its rule, one
  crate source, an A/A subject, the identity check, >= 21 rounds after the differential check, holds
  by construction of `run.sh` and `src/main.rs`. Inputs: a fixed-seed generator within each function's documented preconditions (valid
  MMR sizes for the peak functions, leaf counts below 2^62, LEB128 encodings with one in eight corrupted
  for the readers), plus edge cases; 512 per function. The differential check runs first and must pass;
  then 31 interleaved rounds (the subject order rotates), 5 samples of about 200 µs per subject per
  round, the median of the per-round medians. `samecode.py --family` compares the subjects' machine code,
  following calls into each subject's own copies of the two crates (the addresses of each crate's own
  panic `Location` and message constants are not compared), and again with `--data-blind` (no data
  address compared). Stage finish-A widened the first check's panic rule (all of core's panic entry
  points, the whole argument setup) and taught it the back-references of v0 symbols whose crate names
  differ in length; the identity results were computed with that version on the timed binaries.
- Machine: Apple M5 Pro; rustc 1.98.1 (48a229cea 2026-09-01).

## Reproducing

```sh
cargo test -p commonware-codec; cargo test -p commonware-storage --lib   # verified builds: their OUT_DIRs
HEAVY=<admission wrapper> CARGO_TARGET_DIR=<dir> sandblaster/bench/shipped-harness/run.sh \
    --codec-out <codec OUT_DIR> --storage-out <storage OUT_DIR>   # --rounds N (>= 21)
```
