# Held-out v2 report

**This is the held-out evaluation** (DESIGN.md §8.2 item 11). Held-out v2 was frozen on 2026-10-02
before the reader and optimizer work it judges (`sandblaster/bench/heldout-v2/manifest.toml`, G6): a
second blind H1 set, and H2-v2, monorepo functions sampled afterwards by the versioned rule `h2-v2`
with its committed seed, unchanged, from scope crates development did not look at. Any "faster than
rustc" statement cites this report. Its refusal reasons are now read, so by the held-out-versions
rule a change they motivate moves the function to the development set (H2-v2: its replacement is the
next accepted candidate in the seeded order).

Written by `sandblaster/bench/heldout-harness/run.sh --set v2` (report.py); every number below comes
from that run's result files (`sandblaster/bench/heldout-harness/results/v2/`) and the frozen sample
(`sandblaster/bench/heldout-v2/h2/`). The protocol is the fairness audit's held-out protocol (plan
step 8), unchanged: the optimizer's own output against rustc on the unmodified source, in one binary.

## Headline

**The optimizer changed none of the 30 functions.** Every lowered copy it wrote is the
source byte for byte (`gen/v2/h1.rs` is H1's file; H2-v2 is empty: no candidate passed its probe), so the optimized subject is the rustc subject compiled again. The
optimizer-only geomean is **1.007** (optimized / rustc time, all 30 functions, no exclusions;
default layout, overflow checks on). That is placement noise around 1.00: the A/A
control (the same source compiled twice) spreads 0.867–1.193 in the same binary.
With every function and block aligned to 64 bytes (less placement noise) it is 1.002, A/A spread
0.836–1.109.
The geomean over changed functions is undefined: no function changed.

**H2-v2 is empty**: the frozen rule's probe accepted none of its 869 candidates (shortfall
40; the sample section below and `h2/PROBE-LOG.md`), so this run measures H1-v2 alone.

Of 30 functions, 9 are refused by the lift's MIR reader, 11 by exec-only
elaboration, and 10 reach the optimizer (4 of them through their panic-explicit reading, DESIGN.md §8.2 item 12).
Of those 10, 7 are specialized (0 lowered, 7 kept as written) and
3 not specialized.
No loop is summarized: the 2 functions whose loop reaches the optimizer (`has_pair_with_sum`, `gcd`)
keep it (each reason is in the table below), so none of the loop machinery (closed forms, set-bit
iteration, early exit, unrolling, the aegraph) applies on this set.

## H2-v2: the sample

The rule `h2-v2` (`sandblaster/bench/heldout-v2/h2/RULE.md`, seed `7bc58f68b25930aa17c68e7c870edb9a`) applied unchanged at
the source commit; the decisions its implementation made are in `h2/PROBE-LOG.md`, every rejection
with its reason in `h2/rejections.tsv`, every probed candidate in `h2/probe.tsv`.

Enumeration and the static criteria (RULE.md §1–§3.1): 2293 functions of the scope files are not candidates,
869 are; 131 blocks (inline modules, macro bodies) are not entered.

| reason | functions |
| --- | ---: |
| excluded: test, mock or fuzz file (RULE.md 2.4) | 637 |
| no instance (RULE.md 3.1) | 540 |
| not pure: names an I/O or shared-state token (RULE.md 3) | 416 |
| not pure: async (RULE.md 3) | 183 |
| not enumerated: a trait's own method (RULE.md 3) | 160 |
| excluded: names a target area (RULE.md 2.1) | 145 |
| excluded: under a test/mocks/fuzzing cfg (RULE.md 2.4) | 128 |
| excluded: probed under held-out v1 (RULE.md 2.5) | 53 |
| not a candidate: a closure parameter, Fn/FnMut/FnOnce (RULE.md 3) | 29 |
| not pure: a trait object, dyn (RULE.md 3) | 1 |
| excluded: named like a §15 workload function `parse` (RULE.md 2.3) | 1 |

The probe (RULE.md §5), in the seeded order: 869 candidates probed, 0 accepted, 0 sampled (shortfall 40: RULE.md §4 says H2-v2 is then every candidate that passed, and the rule is not widened).

| first failing step | candidates |
| --- | ---: |
| probe 1 (extraction) | 78 |
| probe 2 (callee closure) | 35 |
| probe 3 (size) | 651 |
| probe 4 (reader) | 104 |
| probe 5 (exec-only) | 1 |

## What was run

- **Set**: held-out v2 (`sandblaster/bench/heldout-v2/manifest.toml`, frozen by G6, dated 2026-10-02,
  source commit `2b3ec7cdc1f3`): H1, 30 functions written blind from a committed idiom list
  (`h1/idioms.md`); H2, every monorepo function the rule `h2-v2` accepted: 0 of the 40 asked for
  (869 candidates, 869 probed, 0 accepted; shortfall 40; the sample, below).
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
  frozen root (and replays its frozen extraction arguments, instance included, for the round trip). No profile exists for
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
- Load average [default-release]: before 10.13 9.71 9.60; after 9.88 9.67 9.59 (a shared, busy host).
- Load average [align-release]: before 9.73 9.64 9.58; after 9.51 9.60 9.56 (a shared, busy host).
- Load average [default-release-nooc]: before 9.39 9.57 9.55; after 9.39 9.57 9.55 (a shared, busy host).

## Results per binary

Ratios are optimized / rustc time (< 1: the optimized subject is faster). The A/A spread (the
noise floor) is the control's range over all functions in that binary.

| binary | geomean, all functions | geomean, changed only | median | best | worst | A/A spread (geomean) | identical code (optimized = rustc) | beyond the A/A spread: faster / slower |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |
| default-release | 1.007 | none changed | 1.000 | 0.905 | 1.194 | 0.867–1.193 (0.988) | 29 of 30 | 0 / 1 |
| align-release | 1.002 | none changed | 0.998 | 0.951 | 1.103 | 0.836–1.109 (0.990) | 29 of 30 | 0 / 0 |
| default-release-nooc | 0.999 | none changed | 0.999 | 0.881 | 1.240 | 0.880–1.279 (0.995) | 29 of 30 | 0 / 0 |

Rows of unchanged functions outside the A/A spread in some binary (count_inversions) are not
optimizer effects: their source text is identical in both subjects. They show how far placement and
a busy host move identical code on this machine; a real gain has to clear that.

## Every function

Optimizer time: the front end, exec-only elaboration, the optimizer, the lowering and its round
trip for that function's root (wall clock, seconds, on the shared host; `+N rt`: the root ran again
after N extractions of the round trip's MIR), and the optimizer's own milliseconds for that root.

| set | function | stage reached | optimizer outcome | changed | opt / rustc [default-release] | opt / rustc [align-release] | opt / rustc [default-release-nooc] | A/A / rustc [default-release] | rounds p10–p90 [default-release] | optimizer time | reason |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | ---: | --- |
| H1 | `parse_u32` | kept | Specialized (Driven) | no | = 1.084 | = 0.998 | = 1.014 | 1.008 | 1.078–1.087 | 0.7 s; opt 14 ms | the residual is not 3% cheaper than the source (portable model: 23336 vs 23586 milli-cycles) |
| H1 | `hex_encode_lower` | reader | — | no | = 1.003 | = 0.996 | = 1.004 | 1.010 | 0.996–1.014 | 0.0 s | error[unsupported]: lift: a constructor of `std::mem::Alignment` |
| H1 | `hex_decode` | reader | — | no | = 0.984 | = 0.995 | = 0.998 | 1.020 | 0.963–1.013 | 0.0 s | error[unsupported]: lift: a constructor of `std::mem::Alignment` |
| H1 | `adler32` | elaboration | — | no | = 1.001 | = 0.998 | = 0.995 | 0.993 | 0.991–1.004 | 0.3 s; opt 13 ms | exec-only elaboration: Blocked("depends on `crate::h1::adler32__loop0`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or |
| H1 | `fletcher16` | elaboration | — | no | = 1.001 | = 1.000 | = 1.004 | 0.999 | 0.999–1.002 | 0.3 s; opt 14 ms | exec-only elaboration: Blocked("depends on `crate::h1::fletcher16__loop0`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` |
| H1 | `luhn_valid` | reader | — | no | = 1.017 | = 0.998 | = 0.993 | 0.910 | 1.002–1.032 | 0.0 s | error[unsupported]: lift: a constructor of `std::iter::Rev` |
| H1 | `manhattan` | kept | Specialized (Driven), through its panic-explicit reading | no | = 0.999 | = 1.000 | = 1.010 | 0.999 | 0.990–1.000 | 1.8 s; opt 15 ms | the residual cannot be printed as Rust: the lift prelude type `crate::__lift::I32` has no host spelling |
| H1 | `rect_intersection_area` | elaboration | — | no | = 0.992 | = 0.988 | = 1.009 | 0.980 | 0.992–0.994 | 18.6 s; opt 5929 ms | exec-only elaboration: Unproven (Unreachable obligation Failed: Empty; Unreachable obligation Failed: Empty; Overflow obligation Failed: Eq(Bool, #le_int(#imul(#cast_u64_int(j), #cast_u64_int(j)), 18446744073709551615int), true)); no panic-explicit reading: its elaboration leaves obligations unprove |
| H1 | `polygon_twice_area` | reader | — | no | = 1.140 | = 1.003 | = 0.994 | 1.001 | 1.123–1.160 | 0.0 s | error[unsupported]: lift: MIR reading of `polygon_twice_area` (in `heldout_h1v2_mir::h1::polygon_twice_area`): checked `mul` of a signed or non-integer type with a tested flag |
| H1 | `is_leap_year` | kept | Specialized (Driven) | no | = 1.000 | = 0.998 | = 0.996 | 0.995 | 0.999–1.000 | 0.2 s; opt 14 ms | the residual is not 3% cheaper than the source (portable model: 7390 vs 7390 milli-cycles); a tie keeps the source |
| H1 | `days_in_month` | elaboration | — | no | = 1.003 | = 0.998 | = 1.240 | 1.000 | 1.000–1.005 | 0.3 s; opt 15 ms | exec-only elaboration: Unproven (Unreachable obligation Failed: Empty); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| H1 | `day_of_week` | kept | Unspecialized, through its panic-explicit reading | no | ≈ 1.013 | ≈ 0.997 | ≈ 0.992 | 0.995 | 1.013–1.036 | 0.5 s; opt 21 ms | optimizer: not stuck-free: a `match` on a neutral scrutinee (primitive Lt(U32)); driven: driven residual not printable: a slice whose list is not a sub-list of a known slice |
| H1 | `day_of_year` | elaboration | — | no | = 0.951 | = 0.993 | = 0.881 | 0.961 | 0.947–0.974 | 0.4 s; opt 16 ms | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| H1 | `seconds_to_hms` | kept | Specialized (StraightLine) | no | = 1.000 | = 1.003 | = 1.005 | 0.992 | 0.983–1.015 | 0.2 s; opt 17 ms | the residual is not 3% cheaper than the source (portable model: 12050 vs 12050 milli-cycles); a tie keeps the source |
| H1 | `count_overlapping_pairs` | elaboration | — | no | = 0.905 | = 0.951 | = 1.003 | 0.867 | 0.706–0.959 | 0.3 s; opt 15 ms | exec-only elaboration: Blocked("depends on `crate::h1::count_overlapping_pairs__loop1`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee |
| H1 | `high_nibble_histogram` | elaboration | — | no | = 1.161 | = 0.979 | = 0.999 | 0.978 | 1.014–1.166 | 0.3 s; opt 14 ms | exec-only elaboration: Blocked("depends on `crate::h1::high_nibble_histogram__loop0`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's |
| H1 | `argmax` | elaboration | — | no | = 1.003 | = 1.016 | = 0.973 | 1.003 | 0.977–1.020 | 0.2 s; opt 14 ms | exec-only elaboration: Blocked("depends on `crate::h1::argmax__loop0`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or  |
| H1 | `min_max` | reader | — | no | = 0.978 | = 1.000 | = 1.002 | 0.998 | 0.968–0.990 | 0.0 s | error[unsupported]: lift: MIR reading of `min_max` (in `core::slice::<impl [u16]>::split_first`): projection (cindex 0 1 false) |
| H1 | `prefix_sums` | reader | — | no | = 0.984 | = 1.079 | = 1.011 | 0.980 | 0.952–1.038 | 0.0 s | error[unsupported]: lift: a constructor of `std::mem::Alignment` |
| H1 | `range_sum` | elaboration | — | no | = 1.001 | = 1.002 | = 1.004 | 1.000 | 0.994–1.019 | 0.2 s; opt 18 ms | exec-only elaboration: Unproven (Unreachable obligation Failed: Empty; Unreachable obligation Failed: Empty; IndexBounds obligation Failed: Eq(Bool, #lt_usize(hi, fst(prefix)), true)); no panic-explicit reading: its elaboration leaves obligations unproven: Unreachable obligation `Empty`; Unreachable |
| H1 | `has_pair_with_sum` | kept | Unspecialized, through its panic-explicit reading | no | = 0.976 | = 1.025 | = 0.967 | 0.942 | 0.941–0.999 | 3.9 s; opt 26 ms | optimizer: not stuck-free: a `match` on a neutral scrutinee (primitive Lt(Usize)); driven: the equality lemma was not proven: a leaf of the process tree is not closed (goal: Eq(Option(Bool), Some(false), Some(crate::h1::has_pair_with_sum__loop0 0usize (#sub_usize(fst(sorted), 1usize)) sorted target) |
| H1 | `dedup_sorted` | reader | — | no | = 1.004 | = 0.987 | = 0.991 | 1.001 | 1.003–1.012 | 0.0 s | error[unsupported]: lift: `dedup_sorted`: rustc's MIR parameter `values` is `&mut` but the lift does not pass it as a state |
| H1 | `lower_bound` | elaboration | — | no | = 0.924 | = 1.000 | = 0.990 | 0.942 | 0.920–0.924 | 0.2 s; opt 17 ms | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| H1 | `rgb565_pack` | kept | Specialized (Driven) | no | = 1.000 | = 0.998 | = 1.000 | 0.999 | 0.987–1.004 | 0.2 s; opt 20 ms | the residual is not 3% cheaper than the source (portable model: 2936 vs 2936 milli-cycles); a tie keeps the source |
| H1 | `rgb565_unpack` | kept | Specialized (StraightLine) | no | = 1.000 | = 1.000 | = 1.000 | 1.000 | 0.989–1.001 | 0.2 s; opt 20 ms | the residual is not 3% cheaper than the source (portable model: 3783 vs 3783 milli-cycles); a tie keeps the source |
| H1 | `gcd` | kept | Unspecialized | no | = 0.932 | = 1.103 | = 0.927 | 0.925 | 0.904–0.991 | 0.2 s; opt 21 ms | optimizer: not stuck-free: a `match` on a neutral scrutinee (`crate::h1::gcd::loop#0`); driven: driven residual not printable: a stuck application of `crate::h1::gcd::loop#0` |
| H1 | `lcm` | kept | Specialized (Driven), through its panic-explicit reading | no | = 1.006 | = 0.998 | = 0.997 | 1.000 | 1.000–1.012 | 0.3 s; opt 24 ms | the residual is not 3% cheaper than the source (portable model: 23692 vs 24067 milli-cycles) (its panic-explicit reading's residual, in its Rust form) |
| H1 | `max_subarray_sum` | reader | — | no | = 0.992 | = 1.003 | = 1.013 | 1.010 | 0.986–0.995 | 0.0 s | error[unsupported]: lift: MIR reading of `max_subarray_sum` (in `core::slice::<impl [i32]>::split_first`): projection (cindex 0 1 false) |
| H1 | `brackets_balanced` | reader | — | no | = 1.007 | = 0.993 | = 0.989 | 0.990 | 0.997–1.011 | 0.0 s | error[unsupported]: lift: a constructor of `std::mem::Alignment` |
| H1 | `count_inversions` | elaboration | — | no | = 1.194 | = 0.985 | = 0.999 | 1.193 | 1.046–1.244 | 0.5 s; opt 19 ms | exec-only elaboration: Blocked("depends on `crate::h1::count_inversions__loop1`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `req |

`=`: the optimized and rustc subjects compiled to the same machine code (samecode.py). A row
without `=` whose function did not change differs only in data addresses the conservative check
compares (for example `crc8`, which rustc compiles to a 256-byte lookup table, one copy per crate:
its A/A pair is not `=` either). A/A pairs identical by the check: 29 of 30 [default-release].
`≈`: the same code except for the addresses of each crate's own constant data (`samecode.py --data-blind`;
the constants' contents are not compared): 30 of 30 optimized = rustc, 30 A/A [default-release], `=` rows included.

## Why: the funnel

| stage | reason | functions |
| --- | --- | --- |
| reader | an allocation (`Vec::with_capacity`, `String::with_capacity`, `Vec::new` grown by `push`): alloc's layout code (`Alignment`) is not read | 4: `hex_encode_lower`, `hex_decode`, `prefix_sums`, `brackets_balanced` |
| reader | `split_first` (a slice pattern with a constant index) is not read | 2: `min_max`, `max_subarray_sum` |
| reader | `.iter().rev()`: core's `Rev` is not modeled | 1: `luhn_valid` |
| reader | a signed checked multiplication (an overflow-checked `*` of a signed type, `saturating_mul`, `for _ in 0..N` over `i32`) is not read | 1: `polygon_twice_area` |
| reader | a `&mut [T]` parameter (a slice updated in place) is not passed as a state | 1: `dedup_sorted` |
| elaboration | unproven (a loop of it did not verify, or a panic no precondition rules out), and no panic-explicit reading: what can fail is where the reading does not read (inside a loop, an `unreachable!()`, a callee's `requires`, an indexed place; DESIGN.md §8.2 item 12) | 9: `adler32`, `fletcher16`, `days_in_month`, `day_of_year`, `count_overlapping_pairs`, `high_nibble_histogram`, `argmax`, `lower_bound`, `count_inversions` |
| elaboration | can panic on some inputs, no contract, and no panic-explicit reading: an `unreachable!()` the prover does not refute (an `assert!`; in MIR a `debug_assert!` is one) is not read (DESIGN.md §8.2 item 12) | 2: `rect_intersection_area`, `range_sum` |
| optimizer | reached the optimizer; the driven residual is not printable as exec code | 1: `day_of_week` |
| optimizer | reached the optimizer, not specialized: the driven candidate's equality proof has a leaf not closed within its budget | 1: `has_pair_with_sum` |
| optimizer | reached the optimizer with a loop: not specialized, the driven residual cannot print the call of the loop the elaborator made (`<f>::loop#k`) | 1: `gcd` |
| lowering | specialized; the residual costs what the source costs: a tie keeps the source (DESIGN.md §8.2 item 6) | 4: `is_leap_year`, `seconds_to_hms`, `rgb565_pack`, `rgb565_unpack` |
| lowering | specialized; the residual is not 3% cheaper than the source (the selection gate) | 2: `parse_u32`, `lcm` |
| lowering | specialized; the residual uses a lift-prelude type with no Rust spelling (`crate::__lift::I32`), so it cannot be printed | 1: `manhattan` |

## Functions the exec-only path leaves unproven (DESIGN.md §8.2 item 12)

A function whose arithmetic, division or indexing no precondition makes safe is `Unproven` in the
exec-only path (and its callers are blocked by it); so is one with a loop that does not verify.
The optimizer works on the panic-explicit reading `f__panics : Option<R>` of each (`None` the
panic), whose residual is linked to it by a kernel-checked equality over `Option<R>`, so no rewrite
adds, removes or moves a panic; a replacement ships only with the panic theorems of the source's MIR
and of the copy's MIR.

| function | reading | optimizer outcome | lowered | reason |
| --- | --- | --- | --- | --- |
| `adler32` | none | — | no | exec-only elaboration: Blocked("depends on `crate::h1::adler32__loop0`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or |
| `fletcher16` | none | — | no | exec-only elaboration: Blocked("depends on `crate::h1::fletcher16__loop0`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` |
| `manhattan` | `manhattan__panics` | Specialized (Driven) | no | the residual cannot be printed as Rust: the lift prelude type `crate::__lift::I32` has no host spelling |
| `rect_intersection_area` | none | — | no | exec-only elaboration: Unproven (Unreachable obligation Failed: Empty; Unreachable obligation Failed: Empty; Overflow obligation Failed: Eq(Bool, #le_int(#imul(#cast_u64_int(j), #cast_u64_int(j)), 18446744073709551615int), true)); no panic-explicit reading: its elaboration leaves obligations unprove |
| `days_in_month` | none | — | no | exec-only elaboration: Unproven (Unreachable obligation Failed: Empty); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| `day_of_week` | `day_of_week__panics` | Unspecialized | no | optimizer: not stuck-free: a `match` on a neutral scrutinee (primitive Lt(U32)); driven: driven residual not printable: a slice whose list is not a sub-list of a known slice |
| `day_of_year` | none | — | no | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| `count_overlapping_pairs` | none | — | no | exec-only elaboration: Blocked("depends on `crate::h1::count_overlapping_pairs__loop1`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee |
| `high_nibble_histogram` | none | — | no | exec-only elaboration: Blocked("depends on `crate::h1::high_nibble_histogram__loop0`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's |
| `argmax` | none | — | no | exec-only elaboration: Blocked("depends on `crate::h1::argmax__loop0`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or  |
| `range_sum` | none | — | no | exec-only elaboration: Unproven (Unreachable obligation Failed: Empty; Unreachable obligation Failed: Empty; IndexBounds obligation Failed: Eq(Bool, #lt_usize(hi, fst(prefix)), true)); no panic-explicit reading: its elaboration leaves obligations unproven: Unreachable obligation `Empty`; Unreachable |
| `has_pair_with_sum` | `has_pair_with_sum__panics` | Unspecialized | no | optimizer: not stuck-free: a `match` on a neutral scrutinee (primitive Lt(Usize)); driven: the equality lemma was not proven: a leaf of the process tree is not closed (goal: Eq(Option(Bool), Some(false), Some(crate::h1::has_pair_with_sum__loop0 0usize (#sub_usize(fst(sorted), 1usize)) sorted target) |
| `lower_bound` | none | — | no | exec-only elaboration: Unproven; no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place) |
| `lcm` | `lcm__panics` | Specialized (Driven) | no | the residual is not 3% cheaper than the source (portable model: 23692 vs 24067 milli-cycles) (its panic-explicit reading's residual, in its Rust form) |
| `count_inversions` | none | — | no | exec-only elaboration: Blocked("depends on `crate::h1::count_inversions__loop1`, which did not verify (checked only against a stand-in body)"); no panic-explicit reading: no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `req |

## The four columns (protocol item 7)

| column | functions | geomean |
| --- | ---: | ---: |
| optimizer-derived (driver, Σ1–Σ5, aegraph, residuals) | 0 | none |
| user `#[rewrite]` alternatives | 0 (excluded by the evaluation option; none exist) | none |
| hand-written hardware variants | 0 (the set has none) | none |
| source restructuring | 0 (the subjects compile the frozen files) | none |

## Rung and lowering hits (protocol item 6)

- Reached the optimizer: 10 of 30 (4 through a panic-explicit reading). Specialized: 7 (Driven 5, StraightLine 2). Unspecialized: 3.
- Candidates per rung (functions with a candidate of that rung; specialized by it): ClosedForm 0/0, SetBits 0/0, EarlyExit 0/0, SkipIdle 0/0, Fused 0/0, Rewritten 0/0, Driven 8/5, StraightLine 10/2.
- Lowered into the source: 0 of 30 in the optimized subject.

## Cost-model decisions (J12)

No function was lowered, so no prediction of a gain can be checked against a measurement.
Kept as written after the cost comparison (residual vs source, portable model): 4 equal in cost (`is_leap_year`, `seconds_to_hms`, `rgb565_pack`, `rgb565_unpack`),
0 dearer, 2 cheaper but not by 3% (`parse_u32`, `lcm`).
A rejected residual is never printed, so there is no second subject to time against the source:
these decisions are not measured here.

## Ablations (protocol item 8, J7)

Not run in this evaluation. The tuned constants (LOOP_TRIPS, the synthesis and guard pools, the 3%
gate, TRY_FAIL, (CP+TP)/2, the popcount surcharge, DERIVE_MIN_PROOF_NODES) can only be ablated where
they act: no function of this set is lowered, and no loop of it is summarized.

## What keeps code unchanged

Counts from this run's reasons. Reading them retires held-out v2 for any change they motivate
(DESIGN.md §8.2 item 11): such a change states its structural justification, and the function it
was read from moves to the development set.

1. **The MIR reader** refuses 9 of 30.
   - 4: an allocation (`Vec::with_capacity`, `String::with_capacity`, `Vec::new` grown by `push`): alloc's layout code (`Alignment`) is not read.
   - 2: `split_first` (a slice pattern with a constant index) is not read.
   - 1: `.iter().rev()`: core's `Rev` is not modeled.
   - 1: a signed checked multiplication (an overflow-checked `*` of a signed type, `saturating_mul`, `for _ in 0..N` over `i32`) is not read.
   - 1: a `&mut [T]` parameter (a slice updated in place) is not passed as a state.
2. **Termination**: 0 functions with a loop over a range that gets no inferred measure.
3. **Unproven in the exec-only path**: 15 functions (a panic no contract rules out, or a loop that does not
   verify, or a callee of either); 4 reach the optimizer through their panic-explicit reading, 11 have none
   (`adler32`, `fletcher16`, `rect_intersection_area`, `days_in_month`, `day_of_year`, `count_overlapping_pairs`, `high_nibble_histogram`, `argmax`, `range_sum`, `lower_bound`, `count_inversions`; each reason is in the tables above).
4. **The optimizer**, on the 10 it saw: 3 not specialized (`day_of_week`, `has_pair_with_sum`, `gcd`); of the 7 specialized,
   0 lowered and 7 kept (equal in cost: 4).

## Reproducing

```sh
HEAVY=<admission wrapper> CARGO_TARGET_DIR=<dir> sandblaster/bench/heldout-harness/run.sh --set v2   # --rounds N (>= 21)
```
