# Held-out evaluation report

Written by `sandblaster/bench/heldout-harness/run.sh` (report.py); every number below comes from
that run's result files (`sandblaster/bench/heldout-harness/results/latest/`). This is the fairness
audit's evaluation protocol (plan step 8): the optimizer's own output on code it was never
developed on, against rustc on the unmodified source, in one binary.

## Headline

**The optimizer changed none of the 31 held-out functions.** Every lowered copy it wrote is the
source byte for byte (`gen/h1.rs` is H1's file; H2's text equals the source's), so the optimized subject is the rustc subject compiled again. The held-out
optimizer-only geomean is **1.020** (optimized / rustc time, all 31 functions, no
exclusions; default layout, overflow checks on). That is placement noise around 1.00: the A/A
control (the same source compiled twice) spreads 0.704–1.791 in the same binary.
With every function and block aligned to 64 bytes (less placement noise) it is 1.005, A/A spread
0.969–1.122.
The geomean over changed functions is undefined: no function changed.

Most of the reason is upstream of the optimizer. Of 31 functions, 22 are refused by
the lift's MIR reader, 6 by exec-only elaboration, and 3 reach the
optimizer. Of those 3, 2 get a residual that is not lowered (not cheaper than the
source, or not replaceable), and 1 is not specialized at all. No loop
reaches the optimizer, so none of its loop machinery (closed forms, set-bit iteration, early exit,
unrolling, the aegraph) is exercised on held-out code.

These are held-out numbers. The QMDB, corpus, codec and storage numbers elsewhere are the
development set; they do not show that the optimizer is general or faster than rustc.

## What was run

- **Held-out set** (`sandblaster/bench/heldout/manifest.toml`, frozen by G6, dated 2026-10-02,
  source commit `729ecd2a215b`): H1, 30 functions written blind from a committed idiom list;
  H2, every monorepo function the sampling rule accepted (1 of the 40 asked for: the rule's probe
  found only one, `commonware-utils::rng::mix64`; shortfall 39, h2/PROBE-LOG.md).
- **Optimizer**: the exec-only path (`elab::Options { exec_only: true }`, no laws, as
  `tests/opt_qmdb.rs`), the production optimizer (`OptOptions::default()`) with only
  `exclude_user_rewrites` set (there are no user `#[rewrite]` alternatives here; the option makes
  sure none is counted), then the in-place lowering with its lifted round trip
  (`driver::lowered::lower_in_place`), through `sandblaster/front/examples/heldout_eval.rs`. H1 is
  lifted in place with `items = "<fn>"`, one root per function (so each refusal is that function's
  own), then once more with every function that passed the reader, which gives the one lowered
  copy the optimized subject compiles. H2 uses its frozen root. No profile exists for the held-out
  set, so every result is without a profile, for both subjects.
- **Harness** (`sandblaster/bench/heldout-harness`, J11): three subjects of one crate source
  (`subject/lib.rs`; the package feature selects the module), linked into one binary: `rustc` (the
  frozen H1 file itself; H2's function text copied verbatim from its file), `A/A` (the same again)
  and `optimized` (the lowered copies). One workspace profile for all three: rustc -O
  (opt-level 3), 16 codegen units, no LTO, no target-cpu flag, no PGO; overflow checks on
  (Commonware's release profile) and, as a second binary, off. No hand-written variant exists in
  the held-out set, so neither subject has one. Inputs: a fixed-seed type-driven generator (uniform
  bit length for integers, short byte strings) respecting each function's documented preconditions,
  plus edge cases; 512 inputs per function. The differential check runs first and must pass;
  then 31 interleaved rounds (the subject order rotates), 5 samples of about 200 µs per subject
  per round, the median of the per-round medians. `samecode.py` compares the subjects' machine code
  (`--ignore-panic-locations`: each crate's own copy of a panic `Location` constant is not compared).
- **Gates run first**: G6 and `fair-baseline.sh --heldout` (one profile, one binary, the identity
  check, an A/A subject, the rustc subject from the frozen source, >= 21 rounds after the check).
- Machine: Apple M5 Pro; rustc 1.98.1 (48a229cea 2026-09-01); worktree HEAD `729ecd2a215b` plus the uncommitted fairness-audit work.
- Load average [default-release]: before 4.23 5.13 4.11; after 4.13 5.10 4.10 (a shared, busy host).
- Load average [align-release]: before 4.12 5.08 4.10; after 4.03 5.04 4.09 (a shared, busy host).
- Load average [default-release-nooc]: before 3.95 5.01 4.09; after 3.87 4.98 4.08 (a shared, busy host).

## Results per binary

Ratios are optimized / rustc time (< 1: the optimized subject is faster). The A/A spread (the
noise floor) is the control's range over all functions in that binary.

| binary | geomean, all functions | geomean, changed only | median | best | worst | A/A spread (geomean) | identical code (optimized = rustc) | beyond the A/A spread: faster / slower |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |
| default-release | 1.020 | none changed | 1.000 | 0.880 | 1.628 | 0.704–1.791 (1.015) | 30 of 31 | 0 / 0 |
| align-release | 1.005 | none changed | 1.001 | 0.958 | 1.160 | 0.969–1.122 (1.002) | 30 of 31 | 1 / 1 |
| default-release-nooc | 0.983 | none changed | 1.000 | 0.692 | 1.130 | 0.845–1.062 (0.989) | 30 of 31 | 2 / 4 |

Rows outside the A/A spread in some binary (binomial_meld_carries, buddy_order, ceil_div, fenwick_prefix_sum, gray_decode, hamming_distance, isqrt, next_power_of_two) are not optimizer effects: their source
text is identical in both subjects. They show how far placement and a busy host move identical code
on this machine; a real gain has to clear that.

## Every function

| set | function | stage reached | optimizer outcome | changed | opt / rustc [default-release] | opt / rustc [align-release] | opt / rustc [default-release-nooc] | A/A / rustc [default-release] | rounds p10–p90 [default-release] | why nothing changed |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| H1 | `decimal_digits` | reader | — | no | = 1.000 | = 1.006 | = 1.025 | 1.143 | 0.985–1.027 | error[contract]: `while` loops need a measure |
| H1 | `base32_encoded_len` | elaboration | — | no | = 0.997 | = 1.023 | = 1.000 | 0.933 | 0.986–1.112 | exec-only elaboration: Unproven (Overflow obligation Failed: Eq(Bool, #le_int(#imul(#cast_usize_int(n), #cast_usize_int(8usize)), 18446744073709551615int), true); Overflow obligation Failed: Eq(Bool, #le_int(#imul(#cast_usize_int(__t1), #cast_usize_int(8usize) |
| H1 | `base64_encoded_len` | elaboration | — | no | = 1.000 | = 0.996 | = 0.995 | 0.923 | 0.914–1.087 | exec-only elaboration: Unproven (Overflow obligation Failed: Eq(Bool, #le_int(#imul(#cast_usize_int(__t3), #cast_usize_int(4usize)), 18446744073709551615int), true); Overflow obligation Failed: Eq(Bool, #le_int(#iadd(#cast_usize_int(__t4), #cast_usize_int(3usi |
| H1 | `reverse_bits` | reader | — | no | = 0.999 | = 1.000 | = 1.000 | 1.001 | 0.994–1.007 | error[unsupported]: lift: MIR reading of `reverse_bits` (in `std::cmp::impls::<impl std::cmp::PartialOrd for i32>::lt`): the signed operation `lt` (SEMANTICS.md §19.3 reads bit operations, shifts, negation and truncating casts only) |
| H1 | `gray_encode` | kept | Specialized (StraightLine) | no | = 1.000 | = 1.000 | = 1.000 | 1.000 | 0.993–1.008 | the residual is not 3% cheaper than the source (portable model: 1243 vs 1243 milli-cycles) |
| H1 | `gray_decode` | reader | — | no | = 1.094 | = 1.035 | = 1.130 | 1.791 | 1.059–1.126 | error[contract]: `while` loops need a measure |
| H1 | `next_power_of_two` | kept | Unspecialized | no | = 0.949 | = 0.999 | = 1.122 | 0.945 | 0.926–0.965 | optimizer: not stuck-free: a `match` on a neutral scrutinee (primitive Le(U32)) |
| H1 | `isqrt` | reader | — | no | = 1.018 | = 0.998 | = 1.066 | 0.992 | 1.005–1.026 | error[contract]: `while` loops need a measure |
| H1 | `fenwick_prefix_sum` | reader | — | no | = 1.084 | = 1.001 | = 0.841 | 1.062 | 1.058–1.091 | error[contract]: `while` loops need a measure |
| H1 | `buddy_order` | reader | — | no | = 0.968 | = 0.978 | = 1.075 | 0.965 | 0.942–0.986 | error[contract]: `while` loops need a measure |
| H1 | `binomial_meld_carries` | reader | — | no | = 1.187 | = 1.160 | = 0.980 | 1.095 | 1.172–1.220 | error[unsupported]: lift: MIR reading of `binomial_meld_carries` (in `heldout_h1_mir::h1::binomial_meld_carries`): a loop test with both targets in the loop |
| H1 | `hamming_distance` | reader | — | no | = 0.880 | = 0.958 | = 1.005 | 0.897 | 0.863–0.883 | error[unsupported]: lift: MIR reading of `hamming_distance` (in `std::slice::Iter::<'_, u8>::new`): rvalue (unsupported "rvalue AddressOf(Const, (*_1))") |
| H1 | `run_count` | reader | — | no | = 0.990 | = 1.007 | = 1.003 | 1.007 | 0.979–1.016 | error[unsupported]: lift: MIR reading of `run_count` (in `core::slice::iter::<impl std::iter::IntoIterator for &[u8]>::into_iter`): rvalue (unsupported "rvalue AddressOf(Const, (*_1))") |
| H1 | `first_newline` | reader | — | no | = 0.935 | = 0.982 | = 0.957 | 1.038 | 0.917–0.956 | error[unsupported]: lift: MIR reading of `first_newline` (in `std::slice::Iter::<'_, u8>::new`): rvalue (unsupported "rvalue AddressOf(Const, (*_1))") |
| H1 | `first_printable` | reader | — | no | = 1.092 | = 0.991 | = 0.986 | 0.996 | 1.075–1.104 | error[unsupported]: lift: MIR reading of `first_printable` (in `std::slice::Iter::<'_, u8>::new`): rvalue (unsupported "rvalue AddressOf(Const, (*_1))") |
| H1 | `checked_sum` | reader | — | no | = 1.007 | = 1.001 | = 1.001 | 0.994 | 0.994–1.037 | error[unsupported]: lift: MIR reading of `checked_sum` (in `std::slice::Iter::<'_, u32>::new`): rvalue (unsupported "rvalue AddressOf(Const, (*_1))") |
| H1 | `ring_index` | elaboration | — | no | = 0.999 | = 1.000 | = 0.872 | 1.008 | 0.980–1.011 | exec-only elaboration: Unproven (DivZero obligation Failed: Eq(Bool, #ne_usize(capacity, 0usize), true); Overflow obligation Failed: Eq(Bool, #le_int(#iadd(#cast_usize_int(head), #cast_usize_int(__t1)), 18446744073709551615int), true)) |
| H1 | `align_up` | elaboration | — | no | = 1.000 | = 1.002 | = 1.000 | 1.000 | 0.992–1.005 | exec-only elaboration: Unproven (Unreachable obligation Failed: Empty; Overflow obligation Failed: Eq(Bool, #le_int(#iadd(#cast_u64_int(x), #cast_u64_int(align)), 18446744073709551615int), true); Underflow obligation Failed: Eq(Bool, #le_u64(1u64, __t2), true) |
| H1 | `ceil_div` | elaboration | — | no | = 1.628 | = 1.001 | = 0.692 | 1.114 | 1.618–1.661 | exec-only elaboration: Unproven (DivZero obligation Failed: Eq(Bool, #ne_u32(b, 0u32), true); DivZero obligation Failed: Eq(Bool, #ne_u32(b, 0u32), true); Overflow obligation Failed: Eq(Bool, #le_int(#iadd(#cast_u32_int(__t1), #cast_u32_int(1u32)), 4294967295i |
| H1 | `crc8` | reader | — | no | 1.027 | 1.000 | 0.988 | 1.011 | 1.019–1.033 | error[unsupported]: lift: MIR reading of `crc8` (in `core::slice::iter::<impl std::iter::IntoIterator for &[u8]>::into_iter`): rvalue (unsupported "rvalue AddressOf(Const, (*_1))") |
| H1 | `parity` | reader | — | no | = 1.014 | = 1.001 | = 1.004 | 1.116 | 0.988–1.020 | error[contract]: `while` loops need a measure |
| H1 | `trailing_ones` | reader | — | no | = 0.995 | = 1.015 | = 0.998 | 1.010 | 0.974–1.017 | error[contract]: `while` loops need a measure |
| H1 | `byte_swap` | reader | — | no | = 1.002 | = 1.004 | = 1.000 | 1.000 | 0.991–1.009 | error[unsupported]: lift: MIR reading of `byte_swap` (in `std::cmp::impls::<impl std::cmp::PartialOrd for i32>::lt`): the signed operation `lt` (SEMANTICS.md §19.3 reads bit operations, shifts, negation and truncating casts only) |
| H1 | `nibble_popcount` | elaboration | — | no | = 1.010 | = 1.000 | = 1.000 | 1.008 | 0.995–1.018 | exec-only elaboration: Blocked("depends on `crate::h1::nibble_popcount__loop0`, which could not be elaborated: cannot infer a termination measure; add `#[decreases(e)]` (§4.2)") |
| H1 | `matrix_sum_4x8` | reader | — | no | = 1.001 | = 1.000 | = 1.000 | 0.999 | 0.989–1.016 | error[recursion]: mutual recursion is not supported: crate::h1::matrix_sum_4x8__loop0 → crate::h1::matrix_sum_4x8__loop1 |
| H1 | `seed16_rounds20` | reader | — | no | = 0.998 | = 1.003 | = 1.000 | 0.999 | 0.986–1.006 | error[unsupported]: lift: MIR reading of `seed16_rounds20` (in `core::num::<impl u32>::rotate_left`): the intrinsic `rotate_left` |
| H1 | `count_words` | reader | — | no | = 0.993 | = 0.973 | = 0.983 | 0.995 | 0.843–1.013 | error[unsupported]: lift: MIR reading of `count_words` (in `core::slice::iter::<impl std::iter::IntoIterator for &[u8]>::into_iter`): rvalue (unsupported "rvalue AddressOf(Const, (*_1))") |
| H1 | `scale_sample` | reader | — | no | = 0.996 | = 1.001 | = 1.000 | 0.998 | 0.985–1.108 | error[unsupported]: lift: MIR reading of `scale_sample` (in `heldout_h1_mir::h1::scale_sample`): the cast Int(true, 16) as Int(true, 32) (sign extension is not read) |
| H1 | `remaining_budget` | reader | — | no | = 0.929 | = 1.041 | = 0.852 | 0.704 | 0.858–1.030 | error[unsupported]: lift: MIR reading of `remaining_budget` (in `core::slice::iter::<impl std::iter::IntoIterator for &[u32]>::into_iter`): rvalue (unsupported "rvalue AddressOf(Const, (*_1))") |
| H1 | `read_u32_le` | reader | — | no | = 0.998 | = 1.002 | = 1.005 | 1.041 | 0.974–1.019 | error[unsupported]: lift: MIR reading of `read_u32_le` (in `<std::option::Option<u32> as std::ops::FromResidual<std::option::Option<std::convert::Infallible>>>::from_residual`): a zero-sized value of type std::option::Option<std::convert::Infallible> used as d |
| H2 | `mix64` | kept | Specialized (StraightLine) | no | = 0.997 | = 1.004 | = 1.002 | 0.997 | 0.978–1.018 | a `const fn` (its lowered helpers would have to be `const fn` too; only a `const fn` alternative of a `#[rewrite]` lemma replaces one) |

`=`: the optimized and rustc subjects compiled to the same machine code (samecode.py). A row
without `=` whose function did not change differs only in data addresses the conservative check
compares (for example `crc8`, which rustc compiles to a 256-byte lookup table, one copy per crate:
its A/A pair is not `=` either). A/A pairs identical by the check: 30 of 31 [default-release].

## Why: the funnel

| stage | reason | functions |
| --- | --- | --- |
| reader | slice iteration: core's slice iterator (`Iter::new`, `into_iter`) takes a raw address (`AddressOf`), which the MIR reader does not read | 8: `hamming_distance`, `run_count`, `first_newline`, `first_printable`, `checked_sum`, `crc8`, `count_words`, `remaining_budget` |
| reader | a `while` loop with no termination measure (in-place code carries none; the lift asks for `proof! { decreases(..) }`) | 7: `decimal_digits`, `gray_decode`, `isqrt`, `fenwick_prefix_sum`, `buddy_order`, `parity`, `trailing_ones` |
| reader | `for _ in 0..N` over an `i32` range: `Range::next` compares signed integers, which SEMANTICS.md §19.3 does not read | 2: `reverse_bits`, `byte_swap` |
| reader | a loop test whose two targets are both inside the loop (`while a != 0 || b != 0 || ..`) | 1: `binomial_meld_carries` |
| reader | nested loops: the lift's two loop functions call each other (mutual recursion is not supported) | 1: `matrix_sum_4x8` |
| reader | the `rotate_left` intrinsic is not read | 1: `seed16_rounds20` |
| reader | a sign-extending cast (`i16 as i32`) is not read | 1: `scale_sample` |
| reader | `?` on an `Option` (its residual `Option<Infallible>` is a zero-sized value used as data) | 1: `read_u32_le` |
| elaboration | a panic obligation (overflow or division by zero) that no stated precondition rules out: the function can panic on some inputs, and H1 states no contract the verifier reads | 5: `base32_encoded_len`, `base64_encoded_len`, `ring_index`, `align_up`, `ceil_div` |
| elaboration | no termination measure inferred for a `for` loop over a range (`#[decreases]` needed) | 1: `nibble_popcount` |
| optimizer | reached the optimizer, not specialized: a branch on an argument (`if n <= 1`) is not stuck-free for the straight-line rung, and the driven residual cannot print `Le(Int)` | 1: `next_power_of_two` |
| lowering | reached the optimizer, specialized; the residual is not 3% cheaper than the source (the selection gate) | 1: `gray_encode` |
| lowering | reached the optimizer, specialized; the lowering does not replace a `const fn` (its helpers would have to be `const fn` too) | 1: `mix64` |

## The four columns (protocol item 7)

| column | functions | geomean |
| --- | ---: | ---: |
| optimizer-derived (driver, Σ1–Σ5, aegraph, residuals) | 0 | none |
| user `#[rewrite]` alternatives | 0 (excluded by the evaluation option; none exist) | none |
| hand-written hardware variants | 0 (the held-out set has none) | none |
| source restructuring | 0 (the subjects compile the frozen files) | none |

## Rung and lowering hits (protocol item 6)

- Reached the optimizer: 3 of 31. Specialized: 2 (StraightLine 2). Unspecialized: 1.
- ClosedForm 0, SetBits 0, EarlyExit 0, SkipIdle 0, Fused 0, Rewritten (aegraph) 0, Driven 0 (1 attempt refused: driven residual not printable: primitive Le(Int) cannot be printed).
- Lowered into the source: 0 of 31.

## Cost-model decision accuracy on held-out pairs (J12)

Candidate pairs with a measured winner: **0**. Accuracy is undefined (n = 0). The only held-out decision
the cost model made is 1 source-vs-residual comparison (`gray_encode`: equal cost, so the source stays). A rejected residual
is never printed, so there is no second subject to time against the source.
`mix64`'s residual is refused before any cost comparison (a `const fn`), and `next_power_of_two` has
no residual. The cost model is therefore unvalidated on held-out code; its three M5 decisions remain
development-set regression checks only (front/tests/opt_cost.rs).

## Ablations (protocol item 8, J7)

The guards stage removed the fixed unroll limit (J7: `drive::unroll_pays` decides by the cost model),
so there is no `max_static_trips` value left to ablate. The remaining tuned constants (LOOP_TRIPS,
the synthesis and guard pools, the 3% gate, TRY_FAIL, (CP+TP)/2, the popcount surcharge,
DERIVE_MIN_PROOF_NODES) were not ablated on this set: no held-out loop reaches the optimizer, and
the three functions that do reach it are decided before any of them applies (equal cost under any
gate of 0–5%, a `const fn`, an unprintable branch). An ablation here would measure nothing; it
becomes meaningful when held-out loops reach the optimizer.

## What would let the optimizer see held-out code (future items; not done here)

Recorded, not acted on: this stage does not change the optimizer or the reader in response to
held-out results. Any item below that is implemented because of a held-out function moves that
function to the development set; H1's replacement is a new function written blind from the same
idiom, and H2's rule has no candidate left (a wider rule is a new, versioned rule).

1. **The MIR reader** refuses 22 of 31: slice iterators (`AddressOf` in core's `Iter`), signed
   comparison (any `for _ in 0..N` whose range is `i32`), the `rotate_left` intrinsic, sign-extending
   casts, `?` on `Option`, a loop test with both targets in the loop, and nested loops (mutual
   recursion of the lift's loop functions). Ordinary Rust uses all of these.
2. **Termination**: in-place code has no `decreases`; the lift asks for one on every `while` loop
   (7 functions), and 1 `for` loop over a range gets no inferred measure. Without an attachment
   per loop, no loop of unannotated code reaches the optimizer.
3. **Contracts**: 5 functions can genuinely panic (overflow, division by zero) for some inputs; the
   verifier is right to refuse them until a precondition is stated.
4. **The optimizer itself**, on the 3 it saw: it cannot print a residual that branches on an
   argument (`next_power_of_two`: the straight-line rung is not stuck-free on `if n <= 1`, and the
   driven residual cannot print `Le(Int)`); the lowering never replaces a `const fn` (`mix64`);
   and where it does produce a residual (`gray_encode`) the residual is the source.

## Reproducing

```sh
HEAVY=<admission wrapper> CARGO_TARGET_DIR=<dir> sandblaster/bench/heldout-harness/run.sh   # --rounds N (>= 21)
```
