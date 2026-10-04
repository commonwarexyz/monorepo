# Held-out v1 report (development set)

**This is a development-set report.** Held-out v1 was retired to the development set on
2026-10-02 (`sandblaster/bench/heldout/README.md`): its refusal reasons were read, and they have
motivated reader and optimizer changes since. Its numbers are regression checks. They do not show
that the optimizer is general, and a "faster than rustc" statement never cites them (DESIGN.md
§8.2 item 11): the held-out evaluation is held-out v2 (`sandblaster/bench/heldout-v2/`).

Written by `sandblaster/bench/heldout-harness/run.sh` (report.py); every number below comes from
that run's result files (`sandblaster/bench/heldout-harness/results/latest/`). The protocol is the
fairness audit's held-out protocol (plan step 8), unchanged: the optimizer's own output against
rustc on the unmodified source, in one binary.

## Headline

**The optimizer changed 3 of the 31 functions** (`next_power_of_two`, `read_u32_le`, `mix64`).
Optimized / rustc time, geomean over all 31 functions, no exclusions: **1.002**; over the
changed functions timed: **1.025** (default layout, overflow checks on). A/A control spread:
0.820–1.291.
Aligned layout: 1.004 over all timed, 1.039 over the changed ones (A/A 0.945–1.023).

Of 31 functions, 7 are refused by the lift's MIR reader, 13 by exec-only
elaboration, and 11 reach the optimizer (4 of them through their panic-explicit reading, DESIGN.md §8.2 item 12).
Of those 11, 7 are specialized (3 lowered, 4 kept as written) and
4 not specialized.
No loop is summarized: the 2 functions whose loop reaches the optimizer (`gray_decode`, `parity`)
keep it (each reason is in the table below), so none of the loop machinery (closed forms, set-bit
iteration, early exit, unrolling, the aegraph) applies on this set.

## What was run

- **Set**: held-out v1 (`sandblaster/bench/heldout/manifest.toml`, frozen by G6, dated 2026-10-02,
  source commit `729ecd2a215b`), development data since 2026-10-02: H1, 30 functions written
  blind from a committed idiom list; H2, every monorepo function the sampling rule accepted (1 of
  the 40 asked for: the rule's probe found only one, `commonware-utils::rng::mix64`; shortfall 39,
  h2/PROBE-LOG.md).
- **Optimizer**: the exec-only path (`elab::Options { exec_only: true }`, no laws, as
  `tests/opt_qmdb.rs`), the production optimizer (`OptOptions::default()`) with only
  `exclude_user_rewrites` set (there are no user `#[rewrite]` alternatives here; the option makes
  sure none is counted), then the in-place lowering with its lifted round trip
  (`driver::lowered::lower_in_place`), through `sandblaster/front/examples/heldout_eval.rs`. A
  function that can panic on some inputs and states no contract is optimized through its
  panic-explicit reading (`f__panics`, `None` the panic; DESIGN.md §8.2 item 12), and is replaced
  only with the kernel's panic theorems of its own MIR and of the replacement's MIR. The round trip
  reads rustc's MIR of each lowered copy (evaluate.py extracts it and runs the root again). H1 is
  lifted in place with `items = "<fn>"` plus the file's types its signature names, one root per
  function (so each refusal is that function's own), then once more with every function that passed
  the reader, which gives the one lowered copy the optimized subject compiles. H2 uses a copy of its
  frozen root. No profile exists for
  this set, so every result is without a profile, for both subjects.
- **Harness** (`sandblaster/bench/heldout-harness`, J11): three subjects of one crate source
  (`subject/lib.rs`; the package feature selects the module), linked into one binary: `rustc` (the
  frozen H1 file itself; H2's function text copied verbatim from its file), `A/A` (the same again)
  and `optimized` (the lowered copies). One workspace profile for all three: rustc -O
  (opt-level 3), 16 codegen units, no LTO, no target-cpu flag, no PGO; overflow checks on
  (Commonware's release profile) and, as a second binary, off. No hand-written variant exists in
  the set, so neither subject has one. Inputs: a fixed-seed type-driven generator (uniform
  bit length for integers, short byte strings) respecting each function's documented preconditions,
  plus edge cases; 512 inputs per function. The differential check runs first and must pass;
  then 31 interleaved rounds (the subject order rotates), 5 samples of about 200 µs per subject
  per round, the median of the per-round medians. `samecode.py` compares the subjects' machine code
  (`--ignore-panic-locations`: the addresses of each crate's own panic `Location` and message constants
  are not compared), and again with `--data-blind` (no data address compared). Stage finish-A widened
  the first check's panic rule to all of core's panic entry points and their whole argument setup, and
  taught it the v0 back-references that the subject crates' different name lengths shift.
- **Gates run first**: G6 and `fair-baseline.sh --heldout` (one profile, one binary, the identity
  check, an A/A subject, the rustc subject from the frozen source, >= 21 rounds after the check).
- Machine: Apple M5 Pro; rustc 1.98.1 (48a229cea 2026-09-01); worktree HEAD `2b3ec7cdc1f3` plus the branch's uncommitted work.
- Load average [default-release]: before 7.28 8.50 9.11; after 7.10 8.44 9.08 (a shared, busy host).
- Load average [align-release]: before 7.17 8.43 9.08; after 7.32 8.44 9.08 (a shared, busy host).
- Load average [default-release-nooc]: before 7.37 8.44 9.07; after 7.34 8.41 9.06 (a shared, busy host).

## Results per binary

Ratios are optimized / rustc time (< 1: the optimized subject is faster). The A/A spread (the
noise floor) is the control's range over all functions in that binary.

| binary | geomean, all functions | geomean, changed only | median | best | worst | A/A spread (geomean) | identical code (optimized = rustc) | beyond the A/A spread: faster / slower |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |
| default-release | 1.002 | 1.025 | 1.000 | 0.835 | 1.128 | 0.820–1.291 (1.016) | 28 of 31 | 0 / 0 |
| align-release | 1.004 | 1.039 | 1.000 | 0.939 | 1.117 | 0.945–1.023 (0.996) | 28 of 31 | 1 / 6 |
| default-release-nooc | 0.952 | 1.019 | 0.999 | 0.402 | 1.445 | 0.395–1.246 (0.957) | 29 of 31 | 0 / 1 |

Rows of unchanged functions outside the A/A spread in some binary (base64_encoded_len, buddy_order, ceil_div, fenwick_prefix_sum, first_newline, hamming_distance, remaining_budget) are not
optimizer effects: their source text is identical in both subjects. They show how far placement and
a busy host move identical code on this machine; a real gain has to clear that.

## Every function

Optimizer time: the front end, exec-only elaboration, the optimizer, the lowering and its round
trip for that function's root (wall clock, seconds, on the shared host; `+N rt`: the root ran again
after N extractions of the round trip's MIR), and the optimizer's own milliseconds for that root.

| set | function | stage reached | optimizer outcome | changed | opt / rustc [default-release] | opt / rustc [align-release] | opt / rustc [default-release-nooc] | A/A / rustc [default-release] | rounds p10–p90 [default-release] | optimizer time | reason |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | ---: | --- |
| H1 | `decimal_digits` | elaboration | — | no | = 0.951 | = 0.992 | = 0.402 | 1.291 | 0.949–0.953 | 0.6 s; opt 14 ms | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| H1 | `base32_encoded_len` | kept | Unspecialized, through its panic-explicit reading | no | = 1.114 | = 0.975 | = 1.000 | 1.114 | 1.081–1.206 | 0.2 s; opt 19 ms | optimizer: not stuck-free: a `match` on a neutral scrutinee (variable #1); driven: the equality lemma was not proven: a leaf of the process tree is not closed within its budget (100000 steps: budget exhausted) |
| H1 | `base64_encoded_len` | kept | Unspecialized, through its panic-explicit reading | no | = 0.930 | = 1.041 | = 0.998 | 1.028 | 0.903–0.926 | 0.3 s; opt 17 ms | optimizer: not stuck-free: a `match` on a neutral scrutinee (variable #1); driven: the equality lemma was not proven: the residual and the source split on different scrutinees |
| H1 | `reverse_bits` | elaboration | — | no | = 1.000 | = 1.000 | = 1.006 | 1.000 | 0.971–1.000 | 0.2 s; opt 19 ms | exec-only elaboration: Blocked("depends on `crate::h1::reverse_bits__loop0`, which could not be elaborated: cannot infer a termination measure; add `#[decreases(e)]` (§4.2)"); no panic-explicit reading: it calls `crate::h1::reverse_bits__loop0`, which is neither kernel-checked nor read (it has no pa |
| H1 | `gray_encode` | kept | Specialized (StraightLine) | no | = 1.000 | = 1.000 | = 0.998 | 1.000 | 0.999–1.003 | 0.2 s; opt 19 ms | the residual is not 3% cheaper than the source (portable model: 1243 vs 1243 milli-cycles); a tie keeps the source |
| H1 | `gray_decode` | kept | Unspecialized | no | = 1.128 | = 0.997 | = 0.742 | 0.971 | 1.127–1.258 | 0.2 s; opt 17 ms | optimizer: not stuck-free: a `match` on a neutral scrutinee (`crate::h1::gray_decode::loop#0`); driven: driven residual not printable: a stuck application of `crate::h1::gray_decode::loop#0` |
| H1 | `next_power_of_two` | lowered | Specialized (Driven) | yes | 0.999 | 1.003 | = 0.980 | 0.992 | 0.995–1.008 | 2.7 s (+1 rt); opt 39 ms | lowered: rung Driven, portable cost 5119 -> 4619 milli-cycles |
| H1 | `isqrt` | elaboration | — | no | = 1.003 | = 1.008 | = 1.005 | 1.032 | 0.998–1.048 | 0.2 s; opt 16 ms | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| H1 | `fenwick_prefix_sum` | elaboration | — | no | = 0.977 | = 1.025 | = 0.985 | 0.958 | 0.970–0.982 | 0.2 s; opt 16 ms | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| H1 | `buddy_order` | elaboration | — | no | = 1.056 | = 1.100 | = 1.053 | 0.984 | 1.035–1.087 | 0.2 s; opt 17 ms | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| H1 | `binomial_meld_carries` | elaboration | — | no | = 1.018 | = 0.947 | = 1.024 | 1.022 | 0.999–1.023 | 0.6 s; opt 18 ms | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| H1 | `hamming_distance` | reader | — | no | = 1.056 | = 1.024 | = 0.995 | 1.041 | 1.036–1.088 | 0.0 s | error[unsupported]: lift: MIR reading of `hamming_distance` (in `<std::slice::Iter<'_, u8> as std::iter::Iterator>::size_hint`): the cast `transmute` of Unsupported("type RawPtr(Ty { id: 33, kind: RigidTy(Uint(U8)) }, Not)") to Adt("std::ptr::NonNull<u8>") |
| H1 | `run_count` | elaboration | — | no | = 1.024 | = 1.004 | = 1.000 | 1.055 | 1.023–1.024 | 3.6 s; opt 15 ms | exec-only elaboration: Blocked("depends on `crate::h1::run_count__loop0`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires`  |
| H1 | `first_newline` | reader | — | no | = 0.939 | = 1.034 | = 0.999 | 0.949 | 0.938–0.940 | 0.0 s | error[unsupported]: lift: MIR reading of `first_newline` (in `heldout_h1_mir::h1::first_newline`): the library function `<std::slice::Iter<'_, u8> as std::iter::Iterator>::position::<{closure@lib.rs:166:26: 166:30}>` has a loop (library loops are not inlined) |
| H1 | `first_printable` | reader | — | no | = 1.011 | = 0.995 | = 0.985 | 1.014 | 1.008–1.014 | 0.0 s | error[unsupported]: lift: a constructor of `std::iter::Enumerate` |
| H1 | `checked_sum` | reader | — | no | = 0.998 | = 0.957 | = 0.921 | 1.011 | 0.985–1.017 | 0.0 s | error[unsupported]: lift: a constructor of `std::iter::Enumerate` |
| H1 | `ring_index` | kept | Specialized (Driven), through its panic-explicit reading | no | = 1.007 | = 1.000 | = 1.065 | 0.993 | 0.959–1.056 | 0.2 s; opt 20 ms | the residual is not 3% cheaper than the source (portable model: 6545 vs 6545 milli-cycles); a tie keeps the source (its panic-explicit reading's residual, in its Rust form) |
| H1 | `align_up` | elaboration | — | no | = 0.997 | = 1.000 | = 1.000 | 0.996 | 0.984–0.998 | 0.2 s; opt 19 ms | exec-only elaboration: Unproven (Unreachable obligation Failed: Empty; Overflow obligation Failed: Eq(Bool, #le_int(#iadd(#cast_u64_int(x), #cast_u64_int(align)), 18446744073709551615int), true); Underflow obligation Failed: Eq(Bool, #le_u64(1u64, __t2), true)); no panic-explicit reading: its elabor |
| H1 | `ceil_div` | kept | Specialized (Driven), through its panic-explicit reading | no | = 0.980 | = 1.000 | = 1.445 | 1.271 | 0.952–0.981 | 0.2 s; opt 21 ms | the residual is not 3% cheaper than the source (portable model: 6927 vs 6927 milli-cycles); a tie keeps the source (its panic-explicit reading's residual, in its Rust form) |
| H1 | `crc8` | elaboration | — | no | ≈ 1.002 | ≈ 1.000 | ≈ 1.001 | 0.998 | 0.973–1.027 | 0.2 s; opt 16 ms | exec-only elaboration: Blocked("depends on `crate::h1::crc8__loop0`, which was not elaborated: depends on `crate::h1::crc8__loop1`, which could not be elaborated: cannot infer a termination measure; add `#[decreases(e)]` (§4.2)"); no panic-explicit reading: it calls `crate::h1::crc8__loop0`, which i |
| H1 | `parity` | kept | Unspecialized | no | = 0.998 | = 1.000 | = 1.018 | 1.024 | 0.996–1.006 | 0.2 s; opt 16 ms | optimizer: not stuck-free: a `match` on a neutral scrutinee (`crate::h1::parity::loop#0`); driven: driven residual not printable: a stuck application of `crate::h1::parity::loop#0` |
| H1 | `trailing_ones` | elaboration | — | no | = 0.990 | = 0.996 | = 1.027 | 0.997 | 0.987–1.017 | 0.2 s; opt 14 ms | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| H1 | `byte_swap` | reader | — | no | = 1.001 | = 1.000 | = 0.513 | 1.000 | 0.978–1.006 | 0.0 s | error[unsupported]: lift: MIR reading of `byte_swap` (in `heldout_h1_mir::h1::byte_swap`): checked `mul` of a signed or non-integer type with a tested flag |
| H1 | `nibble_popcount` | elaboration | — | no | = 1.000 | = 1.017 | = 0.984 | 1.000 | 0.961–1.015 | 0.2 s; opt 15 ms | exec-only elaboration: Blocked("depends on `crate::h1::nibble_popcount__loop0`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requ |
| H1 | `matrix_sum_4x8` | elaboration | — | no | = 1.000 | = 1.000 | = 0.990 | 1.000 | 0.999–1.001 | 0.3 s; opt 15 ms | exec-only elaboration: Blocked("depends on `crate::h1::matrix_sum_4x8__loop1`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requi |
| H1 | `seed16_rounds20` | elaboration | — | no | = 1.000 | = 1.000 | = 1.000 | 1.000 | 0.999–1.000 | 0.2 s; opt 14 ms | exec-only elaboration: Blocked("depends on `crate::h1::seed16_rounds20__loop0`, which was not elaborated: depends on `crate::h1::seed16_rounds20__loop1`, which could not be elaborated: cannot infer a termination measure; add `#[decreases(e)]` (§4.2)"); no panic-explicit reading: it calls `crate::h1: |
| H1 | `count_words` | reader | — | no | = 1.006 | = 0.985 | = 0.982 | 0.996 | 1.000–1.007 | 0.0 s | error[resolve]: cannot find type `State` in this scope |
| H1 | `scale_sample` | reader | — | no | = 1.000 | = 1.000 | = 0.999 | 1.000 | 0.973–1.044 | 0.0 s | error[unsupported]: lift: MIR reading of `scale_sample` (in `core::num::<impl i32>::saturating_mul`): checked `mul` of a signed or non-integer type with a tested flag |
| H1 | `remaining_budget` | kept | Specialized (StraightLine) | no | = 0.835 | = 0.939 | = 0.900 | 0.820 | 0.829–0.837 | 0.2 s; opt 15 ms | the residual is not 3% cheaper than the source (portable model: 64928 vs 64928 milli-cycles); a tie keeps the source |
| H1 | `read_u32_le` | lowered | Specialized (Driven) | yes | 1.079 | 1.117 | 1.071 | 1.040 | 1.072–1.081 | 3.7 s (+1 rt); opt 38 ms | lowered: rung Driven, portable cost 2970 -> 2071 milli-cycles |
| H2 | `mix64` | lowered | Specialized (StraightLine) | yes | = 1.000 | = 1.000 | = 1.007 | 0.991 | 0.957–1.011 | 2.5 s (+1 rt); opt 16 ms | lowered: rung StraightLine, portable cost 7449 -> 7075 milli-cycles |

`=`: the optimized and rustc subjects compiled to the same machine code (samecode.py). A row
without `=` whose function did not change differs only in data addresses the conservative check
compares (for example `crc8`, which rustc compiles to a 256-byte lookup table, one copy per crate:
its A/A pair is not `=` either). A/A pairs identical by the check: 30 of 31 [default-release].
`≈`: the same code except for the addresses of each crate's own constant data (`samecode.py --data-blind`;
the constants' contents are not compared): 29 of 31 optimized = rustc, 31 A/A [default-release], `=` rows included.

## Change since the previous run

The previous run (its `eval.json`, `--previous`; run.sh passes the one its run replaces): 7 refused by the reader, 13 by exec-only
elaboration, 11 reached the optimizer, 3 lowered. This run: 7, 13, 11, 3.

No function's stage, outcome or lowering changed.

## Why: the funnel

| stage | reason | functions |
| --- | --- | --- |
| reader | `.iter().enumerate()`: core's `Enumerate` is not modeled | 2: `first_printable`, `checked_sum` |
| reader | a signed checked multiplication (an overflow-checked `*` of a signed type, `saturating_mul`, `for _ in 0..N` over `i32`) is not read | 2: `byte_swap`, `scale_sample` |
| reader | slice iteration: core's slice iterator's `size_hint` transmutes a raw pointer, which the MIR reader does not read | 1: `hamming_distance` |
| reader | a library function with a loop (`Iterator::position`): library loops are not inlined | 1: `first_newline` |
| reader | the lift does not resolve a type the file declares (`State`) | 1: `count_words` |
| elaboration | unproven (a loop of it did not verify, or a panic no precondition rules out), and no panic-explicit reading: what can fail is where the reading does not read (inside a loop, an `unreachable!()`, a callee's `requires`, an indexed place; DESIGN.md §8.2 item 12) | 9: `decimal_digits`, `isqrt`, `fenwick_prefix_sum`, `buddy_order`, `binomial_meld_carries`, `run_count`, `trailing_ones`, `nibble_popcount`, `matrix_sum_4x8` |
| elaboration | no termination measure inferred for a `for` loop over a range (`#[decreases]` needed) | 3: `reverse_bits`, `crc8`, `seed16_rounds20` |
| elaboration | can panic on some inputs, no contract, and no panic-explicit reading: an `unreachable!()` the prover does not refute (an `assert!`; in MIR a `debug_assert!` is one) is not read (DESIGN.md §8.2 item 12) | 1: `align_up` |
| optimizer | reached the optimizer with a loop: not specialized, the driven residual cannot print the call of the loop the elaborator made (`<f>::loop#k`) | 2: `gray_decode`, `parity` |
| optimizer | reached the optimizer, not specialized: the driven candidate's equality proof has a leaf not closed within its budget | 1: `base32_encoded_len` |
| optimizer | reached the optimizer, not specialized: the driven candidate's equality proof finds the residual and the source splitting on different scrutinees | 1: `base64_encoded_len` |
| lowering | specialized; the residual costs what the source costs: a tie keeps the source (DESIGN.md §8.2 item 6) | 4: `gray_encode`, `ring_index`, `ceil_div`, `remaining_budget` |
| lowered | lowered: the optimizer's residual replaces the source, accepted by the lifted round trip | 3: `next_power_of_two`, `read_u32_le`, `mix64` |

## Functions the exec-only path leaves unproven (DESIGN.md §8.2 item 12)

A function whose arithmetic, division or indexing no precondition makes safe is `Unproven` in the
exec-only path (and its callers are blocked by it); so is one with a loop that does not verify.
The optimizer works on the panic-explicit reading `f__panics : Option<R>` of each (`None` the
panic), whose residual is linked to it by a kernel-checked equality over `Option<R>`, so no rewrite
adds, removes or moves a panic; a replacement ships only with the panic theorems of the source's MIR
and of the copy's MIR.

| function | reading | optimizer outcome | lowered | reason |
| --- | --- | --- | --- | --- |
| `decimal_digits` | none | — | no | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| `base32_encoded_len` | `base32_encoded_len__panics` | Unspecialized | no | optimizer: not stuck-free: a `match` on a neutral scrutinee (variable #1); driven: the equality lemma was not proven: a leaf of the process tree is not closed within its budget (100000 steps: budget exhausted) |
| `base64_encoded_len` | `base64_encoded_len__panics` | Unspecialized | no | optimizer: not stuck-free: a `match` on a neutral scrutinee (variable #1); driven: the equality lemma was not proven: the residual and the source split on different scrutinees |
| `reverse_bits` | none | — | no | exec-only elaboration: Blocked("depends on `crate::h1::reverse_bits__loop0`, which could not be elaborated: cannot infer a termination measure; add `#[decreases(e)]` (§4.2)"); no panic-explicit reading: it calls `crate::h1::reverse_bits__loop0`, which is neither kernel-checked nor read (it has no pa |
| `isqrt` | none | — | no | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| `fenwick_prefix_sum` | none | — | no | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| `buddy_order` | none | — | no | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| `binomial_meld_carries` | none | — | no | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| `run_count` | none | — | no | exec-only elaboration: Blocked("depends on `crate::h1::run_count__loop0`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires`  |
| `ring_index` | `ring_index__panics` | Specialized (Driven) | no | the residual is not 3% cheaper than the source (portable model: 6545 vs 6545 milli-cycles); a tie keeps the source (its panic-explicit reading's residual, in its Rust form) |
| `align_up` | none | — | no | exec-only elaboration: Unproven (Unreachable obligation Failed: Empty; Overflow obligation Failed: Eq(Bool, #le_int(#iadd(#cast_u64_int(x), #cast_u64_int(align)), 18446744073709551615int), true); Underflow obligation Failed: Eq(Bool, #le_u64(1u64, __t2), true)); no panic-explicit reading: its elabor |
| `ceil_div` | `ceil_div__panics` | Specialized (Driven) | no | the residual is not 3% cheaper than the source (portable model: 6927 vs 6927 milli-cycles); a tie keeps the source (its panic-explicit reading's residual, in its Rust form) |
| `crc8` | none | — | no | exec-only elaboration: Blocked("depends on `crate::h1::crc8__loop0`, which was not elaborated: depends on `crate::h1::crc8__loop1`, which could not be elaborated: cannot infer a termination measure; add `#[decreases(e)]` (§4.2)"); no panic-explicit reading: it calls `crate::h1::crc8__loop0`, which i |
| `trailing_ones` | none | — | no | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| `nibble_popcount` | none | — | no | exec-only elaboration: Blocked("depends on `crate::h1::nibble_popcount__loop0`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requ |
| `matrix_sum_4x8` | none | — | no | exec-only elaboration: Blocked("depends on `crate::h1::matrix_sum_4x8__loop1`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requi |
| `seed16_rounds20` | none | — | no | exec-only elaboration: Blocked("depends on `crate::h1::seed16_rounds20__loop0`, which was not elaborated: depends on `crate::h1::seed16_rounds20__loop1`, which could not be elaborated: cannot infer a termination measure; add `#[decreases(e)]` (§4.2)"); no panic-explicit reading: it calls `crate::h1: |

## The four columns (protocol item 7)

| column | functions | geomean |
| --- | ---: | ---: |
| optimizer-derived (driver, Σ1–Σ5, aegraph, residuals) | 3 | 1.025 |
| user `#[rewrite]` alternatives | 0 (excluded by the evaluation option; none exist) | none |
| hand-written hardware variants | 0 (the set has none) | none |
| source restructuring | 0 (the subjects compile the frozen files) | none |

## Rung and lowering hits (protocol item 6)

- Reached the optimizer: 11 of 31 (4 through a panic-explicit reading). Specialized: 7 (Driven 4, StraightLine 3). Unspecialized: 4.
- Candidates per rung (functions with a candidate of that rung; specialized by it): ClosedForm 0/0, SetBits 0/0, EarlyExit 0/0, SkipIdle 0/0, Fused 0/0, Rewritten 0/0, Driven 8/4, StraightLine 11/3.
- Lowered into the source: 3 of 31 in the optimized subject (optimizer 3).

## Cost-model decisions (J12)

The model predicted a gain (at least 3%) for the 3 lowered functions. Measured [default-release]:
0 faster beyond the A/A spread (none), 0 slower beyond it (none),
3 within it.

Cost-model accuracy, per lowered function: the portable model's predicted ratio (residual / source
cost) against the measured optimized / rustc time in each binary.

| function | portable cost, source → residual (milli-cycles) | predicted | measured [default-release] | measured [align-release] | measured [default-release-nooc] |
| --- | --- | ---: | ---: | ---: | ---: |
| `next_power_of_two` | 5119 → 4619 | 0.902 | 0.999 | 1.003 | 0.980 |
| `read_u32_le` | 2970 → 2071 | 0.697 | 1.079 | 1.117 | 1.071 |
| `mix64` | 7449 → 7075 | 0.950 | 1.000 | 1.000 | 1.007 |

Geomean predicted 0.842, measured 1.025 [default-release]; the model's direction (a gain) held for 1 of 3 (any gain, inside the noise or not).
Kept as written after the cost comparison (residual vs source, portable model): 4 equal in cost (`gray_encode`, `ring_index`, `ceil_div`, `remaining_budget`),
0 dearer, 0 cheaper but not by 3%.
A rejected residual is never printed, so there is no second subject to time against the source:
these decisions are not measured here.

## Ablations (protocol item 8, J7)

Not run on this set. The tuned constants (LOOP_TRIPS, the synthesis and guard pools, the 3% gate,
TRY_FAIL, (CP+TP)/2, the popcount surcharge, DERIVE_MIN_PROOF_NODES) are ablated on held-out
code; this set is development data now. No loop of this set is summarized either.

## What keeps code unchanged (development notes)

Counts from this run's reasons; this set may motivate changes (it is development data), and each
change states its structural justification (DESIGN.md §8.2 item 11).

1. **The MIR reader** refuses 7 of 31.
   - 2: `.iter().enumerate()`: core's `Enumerate` is not modeled.
   - 2: a signed checked multiplication (an overflow-checked `*` of a signed type, `saturating_mul`, `for _ in 0..N` over `i32`) is not read.
   - 1: slice iteration: core's slice iterator's `size_hint` transmutes a raw pointer, which the MIR reader does not read.
   - 1: a library function with a loop (`Iterator::position`): library loops are not inlined.
   - 1: the lift does not resolve a type the file declares (`State`).
2. **Termination**: 3 functions with a loop over a range that gets no inferred measure.
3. **Unproven in the exec-only path**: 17 functions (a panic no contract rules out, or a loop that does not
   verify, or a callee of either); 4 reach the optimizer through their panic-explicit reading, 13 have none
   (`decimal_digits`, `reverse_bits`, `isqrt`, `fenwick_prefix_sum`, `buddy_order`, `binomial_meld_carries`, `run_count`, `align_up`, `crc8`, `trailing_ones`, `nibble_popcount`, `matrix_sum_4x8`, `seed16_rounds20`; each reason is in the tables above).
4. **The optimizer**, on the 11 it saw: 4 not specialized (`base32_encoded_len`, `base64_encoded_len`, `gray_decode`, `parity`); of the 7 specialized,
   3 lowered and 4 kept (equal in cost: 4).

## Reproducing

```sh
HEAVY=<admission wrapper> CARGO_TARGET_DIR=<dir> sandblaster/bench/heldout-harness/run.sh --set v1   # --rounds N (>= 21)
```
