# Held-out evaluation harness

The fairness audit's evaluation protocol (2026-10-02, plan step 8, J9, J11,
J12): the optimizer's own output on code it was never developed on, timed
against rustc on the unmodified source. The held-out set itself is frozen in
`sandblaster/bench/heldout/` (G6); this directory only reads it. The report
it produces is `sandblaster/bench/heldout/REPORT.md`.

```sh
HEAVY=<admission wrapper> CARGO_TARGET_DIR=<dir> sandblaster/bench/heldout-harness/run.sh   # [--rounds N (>= 21)]
```

`run.sh` is the only script that reads optimizer output or timings on the
held-out set (protocol item 3). A held-out result that motivates an optimizer
change moves that function to the development set; its replacement is drawn
by the same rule.

## Pieces

| file | what |
| --- | --- |
| `run.sh` | gates (G6, `fair-baseline.sh --heldout`), extraction, the optimizer, the timed binaries, the report |
| `extract/` | MIR extraction only: H1's frozen `src/lib.rs` as module `h1` (`extract/h1` is a symlink to `../../heldout/h1`, so the `.sbmir` names the source `h1/src/lib.rs`, a suffix of the path the DSL roots lift) |
| `h1/h1.sbmir` | rustc's MIR of H1 (pinned nightly, deterministic; re-extracted by every run) |
| `evaluate.py` | the exec-only optimizer on every H1 function (one DSL root per function, `items = "<fn>"`) and every H2 function (its frozen root), through `sandblaster/front/examples/heldout_eval.rs`; then one root with every H1 function that passed the reader, whose lowered copy is `gen/h1.rs` |
| `items.py` | copies a function's text verbatim out of a file (H2's functions live in files that need their crates' dependencies) |
| `subject/lib.rs`, `subject/probe.rs` | the ONE crate source of every subject; the package's feature selects the module |
| `subj_rustc`, `subj_rustc_aa`, `subj_opt` | the subjects: the frozen source, the same again (A/A control), the optimizer's lowered copies |
| `src/main.rs` | the binary: `check` (differential), `bench` (refuses < 21 rounds, runs `check` first) |
| `report.py` | `REPORT.md` from the result files |
| `results/latest/` | the last run: `eval.json`, `bench-*.json/md`, `samecode-*.json`, `check-*.txt`, `load-*.json`, logs |

## Method (fair baseline, J11)

* **One crate, one binary, one profile.** All subjects compile `subject/lib.rs`
  under the workspace profile (opt-level 3, 16 codegen units, no LTO, no
  target-cpu flag, no PGO); `release` keeps overflow checks on (Commonware's
  production profile), `release-nooc` is the same without them. The rustc
  subject is the frozen H1 file itself (`#[path]`), never a trimmed copy;
  H2's function texts are copied verbatim from their files (only
  `#[stability(..)]`, a cfg-gating attribute, is dropped) for both subjects.
  No hand-written variant exists in the held-out set; one would live in the
  shared source, so both subjects would get it.
* **A/A and identity.** `subj_rustc_aa` is the rustc subject again: its ratio
  is the noise floor. `samecode.py --crates subj_rustc,subj_rustc_aa,subj_opt
  --ignore-panic-locations` marks rows whose subjects compiled to the same
  machine code (`=`); each crate's own copy of a panic `Location` constant is
  not compared, any other data address is (so `crc8`, which rustc compiles to
  a lookup table, one copy per crate, is never `=`, not even A/A).
* **Differential check first**, on every input; then at least 21 interleaved
  rounds (the subject order rotates), 5 samples of about 200 µs per subject per
  round, medians. Two layouts (default; every function and block aligned to 64
  bytes) and the no-overflow-check profile, each its own binary. The load
  average is recorded before and after each binary's timings.
* **Inputs**: a fixed-seed, type-driven generator (uniform bit length for
  integers, short byte strings over small alphabets) that respects each
  function's documented preconditions, plus edge cases; 512 per function. No
  profile exists for the held-out set, so every result is without a profile.

`fair-baseline.sh --heldout` checks the structural part of this (one crate
source, one profile, one binary, the A/A subject, the frozen rustc source,
the identity check, >= 21 rounds after the differential check), with negative
twins in `fair-baseline.sh --selftest`.
