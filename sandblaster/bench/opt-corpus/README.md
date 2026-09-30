# Optimizer corpus harness

The native half of the general optimizer corpus (docs/optimizer-plan.md O1):
three subjects per program, differential checks first, then same-binary
timings (§0.3: every subject in one binary, ≥ 3 rounds in rotating order, the
median of the per-round medians):

| subject | crate | what |
| --- | --- | --- |
| current | `cgen` | the corpus (`sandblaster/front/tests/opt_corpus/dsl`) as emitted now, by `run.sh` |
| O1 emission | `cgen_o1` | the corpus as emitted at plan O1, the frozen `baselines/o1-gen.rs` |
| ideal | `ideal` | the hand-written targets |

```sh
HEAVY=<admission wrapper> bench/opt-corpus/run.sh            # full run, both layouts (~4 min)
HEAVY=... bench/opt-corpus/run.sh --quick --rounds 1 --only P15,P16 --no-x86 --layouts default
HEAVY=... bench/opt-corpus/run.sh --record                   # re-record recorded.tsv's P15-P20 rows
```

**Judging a milestone.** A gain is `O1 / current` *within one binary*, in
both layouts (`gains.md`: the smallest value over the layouts). Never compare
timings across binaries: what is linked into a binary moves every function's
code, and identical code can move by double-digit percentages. At O2, adding
`cgen_o1` moved P20's unchanged code +17% in the default layout (91.5 vs 78
ns); in one binary, P20's current and O1 emissions — the same machine code —
time within 1.4% (default) and 0.2% (aligned).

`samecode.py` checks, per binary, which programs' current and O1 emissions
compiled to the same machine code (following calls, ignoring addresses and
alignment padding). Their `O1 / current` is placement noise alone: `gains.md`
marks those rows `=` and prints their spread per layout, the noise floor a gain
must clear. At O2 every row is identical code in the release binaries (E0 only
changes overflow-checked builds), and the spread was 0.861–1.059 (default) and
0.941–1.365 (aligned; the extreme is P6 `x < 34`, a sub-ns row). Only P18
under `overflow-checks = true` differs: 1.43× in both layouts.

**Layouts** (`--layouts default,align`, both by default): `default` is plain
`--release`; `align` builds with every function and non-fallthrough block
aligned to 64 bytes, an alternative placement of all three subjects. Each
layout is its own binary with its own checks, timings and `samecode` result.

**Recorded values** (`recorded.tsv`, read at run time, never compiled in): the
`recorded` column. P1–P14 are the values from when the corpus was designed
(design §2.3); P15–P20 are the O1 emission / ideal as re-recorded by `run.sh
--record`, for the *harness composition* named in the file: the sha256 of
every harness source compiled into the binary, the frozen O1 emission and
`rustc -vV` (not the current emission, which changes by design; the in-binary
O1 subject absorbs that). `run.sh` recomputes the composition. When it differs
(a harness change, a new subject, a toolchain update), the run still reports
everything, then fails with exit 3 until the rows are re-recorded with
`--record` (a full run including the default layout; the previous file is
appended to `recorded-history.tsv`). `run.sh --composition` only compares (exit 0
when it matches, 3 when not; nothing is built).

What a run does:
1. emits the corpus for aarch64 and x86_64 with the front end's stage
   emitter (`cargo run -p sandblaster-front --example stage_emit`: proofs,
   optimizer, printer and round trip; the corpus is a toolchain test program,
   so its file says `STATUS: STAGE OUTPUT`, which only `cgen` accepts, DESIGN.md
   §15.8) under `SANDBLASTER_STRICT_OPT=1` (an optimizer warning fails the run,
   gate G2);
2. aarch64, per layout: `check` (400k integers, 1.3M varint byte strings,
   folds, tables, scans for P1–P14; P15–P20 cases, including all 65,536
   GF(2^16) multipliers; the ideal and the O1 emission against the current
   emission), `check-reject` (the checks must catch every must-reject variant
   of P15–P20, `ideal::reject`), `samecode.py`, `bench`, P18 again under
   `overflow-checks = true` (profile `release-oc`, the E0 target), and `e0`;
3. `gains.md` over the layouts; `--record` rewrites recorded.tsv's P15–P20 rows;
4. x86_64: `x86_64-apple-darwin` builds at `x86-64` and `x86-64-v3` whose checks
   run under Rosetta 2, and a compile-only `x86_64-unknown-linux-gnu` build at
   `x86-64-v4` (objects generated, the link stubbed by
   `tools/asmcheck/nolink.sh`).

Results land in `target/opt/opt-corpus/<date>/` (emitted files, logs,
`bench-aarch64-<layout>[-oc].json/md`, `samecode-*.json`, `e0-*.md`,
`gains.md`, `summary.md`).

P18 is timed on `mul_carry_limbs`, the precondition-bounded kernel called
directly, so rustc cannot see the limb bounds and keeps every overflow check
under `release-oc`.

**E0 (plan O2).** `opt-corpus e0` times P18's kernel as emitted now (proven
operations through the `crate::__rt::chk` helpers), as emitted at O1 (checked
operators; the frozen `baselines/o1-gen.rs`, crate `cgen_o1`) and the ideal, in
one binary, after checking all three against the exact product. `run.sh` runs it
in each layout's `release-oc` binary (`e0-<layout>-oc.md`: the E0 target, O1
printing / current ≥ 1.5×) and release binary (`e0-<layout>.md`: the control,
where all three compile alike). The `bench` P18 row under overflow checks
measures the same two functions in the bench loop (direct calls, its own
inputs) and reads lower: 1.43× against `e0`'s 1.56–1.57× in the same binaries
(this file's first three-subject run).
