# Held-out evaluation harness

The fairness audit's evaluation protocol (2026-10-02, plan step 8, J9, J11,
J12): the optimizer's own output on code it was never developed on, timed
against rustc on the unmodified source, in one binary. The held-out sets
are frozen in `sandblaster/bench/heldout-v2/` (held-out v2, the held-out
set) and `sandblaster/bench/heldout/` (held-out v1, development data since
2026-10-02), both under G6; this directory only reads them. Its reports are
`sandblaster/bench/heldout-v2/REPORT.md` and `sandblaster/bench/heldout/REPORT.md`.

```sh
HEAVY=<admission wrapper> CARGO_TARGET_DIR=<dir> sandblaster/bench/heldout-harness/run.sh            # held-out v2 [--rounds N (>= 21)]
HEAVY=<admission wrapper> CARGO_TARGET_DIR=<dir> sandblaster/bench/heldout-harness/run.sh --set v1   # held-out v1, development data
```

**Held-out v2 is the held-out evaluation** (`--set v2`, the default):
H1-v2, 30 functions written blind from a committed idiom list, and H2-v2,
the monorepo functions the versioned rule `h2-v2` sampled after the reader
work (`sandblaster/bench/heldout-v2/h2/`, `sample-manifest.toml`). Its
results are in `results/v2/`. **Held-out v1 is development data since
2026-10-02** (`sandblaster/bench/heldout/README.md`): its refusal reasons
were read and have motivated reader and optimizer changes, so `--set v1`
runs it as a development-set regression check (`results/latest/`), and its
`REPORT.md` is labelled a development-set report. The protocol is the same
for both. Both sets are compiled into every subject (each set's own
modules, `h1`/`h2` and `h1v2`/`h2v2`); the binary times one set
(`check --set`, `bench --set`).

## Pieces

| file | what |
| --- | --- |
| `run.sh` | gates (G6, `fair-baseline.sh --heldout`), extraction, the optimizer, the timed binaries, the report (`--set v1\|v2`) |
| `extract/`, `extract-v2/` | MIR extraction only: v1's (v2's) frozen H1 `src/lib.rs` as module `h1` (`extract/h1` is a symlink to `../../heldout/h1`, `extract-v2/h1` to `../../heldout-v2/h1`, so the `.sbmir` names the source `h1/src/lib.rs`, a suffix of the path the DSL roots lift) |
| `h1/h1.sbmir`, `h1v2/h1.sbmir` | rustc's MIR of v1's and v2's H1 (pinned nightly, deterministic; re-extracted by every run of the set) |
| `evaluate.py` | `--set v1\|v2`: the exec-only optimizer on every H1 function (one DSL root per function, `items = "<fn>"` plus the file's types its signature names) and every H2 function (a copy of its frozen root; v2 replays the probe's frozen extraction arguments, instance included, for the round trip), through `sandblaster/front/examples/heldout_eval.rs`; then one root with every H1 function that passed the reader, whose lowered copy is `gen/h1.rs` (v2: `gen/v2/h1.rs`; v2 also writes `gen/v2/h2_source.rs` and `gen/v2/h2_opt.rs`). A rewrite is accepted only by the lifted round trip, which reads rustc's MIR of the lowered copy: when it asks for it, the copy is extracted (`sandblaster/mirx/extract.sh --replace`) and the root run again. A function that can panic is optimized through its panic-explicit reading (DESIGN.md §8.2 item 12); its record names the reading |
| `items.py` | copies a function's text verbatim out of a file (H2's functions live in files that need their crates' dependencies) |
| `subject/lib.rs`, `subject/probe.rs` | the ONE crate source of every subject; the package's feature selects the module |
| `subj_rustc`, `subj_rustc_aa`, `subj_opt` | the subjects: the frozen source, the same again (A/A control), the optimizer's lowered copies |
| `src/main.rs` | the binary: `check` (differential), `bench` (refuses < 21 rounds, runs `check` first); `--set v1\|v2\|all` picks the cases (v2's rows are `v2_<fn>` and `v2h2_<fn>`) |
| `report.py` | `REPORT.md` from the result files, with each function's stage then and now against the previous run's `eval.json` (`--previous`; `run.sh` keeps it in `$CARGO_TARGET_DIR/heldout-previous-eval.json` before it clears `results/latest/`) |
| `results/v2/`, `results/latest/` | the last run of v2 and of v1: `eval.json`, `bench-*.json/md`, `samecode-*.json`, `check-*.txt`, `load-*.json`, logs |

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
  machine code (`=`); the addresses of each crate's own panic `Location` and
  message constants are not compared, any other data address is (so `crc8`,
  which rustc compiles to a lookup table, one copy per crate, is never `=`,
  not even A/A). The same check with `--data-blind` (`samecode-blind-*.json`)
  compares no data address: `≈` marks code that is the same except for which
  crate's copy of a constant it reads.
* **Which H2 functions are timed** (held-out v2): a function that changed and
  is a free function at no instance (its own text, copied verbatim, compiles
  in each subject). An unchanged one is not timed: the optimized subject would
  compile its source text as written, the same code; the report lists it with
  its outcome and leaves it out of the geomean. A changed method or generic
  instance would need its crate in each subject (not built).
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
