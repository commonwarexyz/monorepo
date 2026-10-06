# Measurement harness (for pilots)

A standalone measurement tool: the original crates at a given commit against
the worktree's own crates, in one binary. A pilot that changes the code of a
verified module (say, an optimized MMR function with its proof) measures the
change here: is the worktree's code faster than the original, by more than
the noise floor, and is it really different machine code?

```sh
# the whole verified surface (varint, MMR, verifier); codec's varint module
# is included from a build's OUT_DIR
cargo build -p commonware-codec
HEAVY=<admission wrapper> CARGO_TARGET_DIR=<dir> sandblaster/bench/shipped-harness/run.sh \
    --out-dir codec=<target>/debug/build/commonware-codec-<hash>/out
# one MMR function (storage only), against a chosen base commit
sandblaster/bench/shipped-harness/run.sh --probe sandblaster/bench/shipped-harness/probes/mmr-smoke \
    --base <rev> --rounds 21 --out <dir>
```

## Pieces

| file | what |
| --- | --- |
| `run.sh` | the subjects, the binaries (layouts, overflow checks), the identity check, the differential check, the timings, the report |
| `prepare.py` | `gen/` (not committed): each subject's copies of the probe's crates under their own package names — `orig` and `aa` from the base commit (`git archive`, read-only), `wt` from this worktree as it is (an include of build output, codec's verified varint module, is copied from `--out-dir`); checks this workspace's `[workspace.dependencies]` against the monorepo's |
| `probes/<name>/` | what is measured (`probes/README`): `probe.rs` (one out-of-line entry per function, the same text in every subject), `rows.rs` (inputs and argument patterns), `crates` |
| `subject/lib.rs` | the ONE crate source of every subject (`gen/subj_*` are its manifests) |
| `src/main.rs` | the binary: `check` (differential), `bench` (refuses < 21 rounds, runs `check` first); `--only F,..` |
| `samecode.py` | the machine-code identity check (aarch64 `objdump`) |
| `report.py` | `REPORT.md` from the result files |

## Method

One workspace profile compiles every subject alike (opt-level 3, 16 codegen
units, no LTO, no target-cpu flag, no PGO; overflow checks on, Commonware's
release profile, and a binary without them; and one with every function and
block aligned to 64 bytes); one crate source for every subject; an A/A
subject (the original code from its own copies: the noise floor); the
machine-code identity check (`samecode.py --family`, which follows calls into
each subject's own copies of the crates, so code compiled from two copies of
the same source compares equal; the addresses of each copy's own panic
constants are not compared), and the same check with `--data-blind` (no data
address compared: code that differs only in which copy of a constant table
it reads compares equal); the differential check first; at least 21
interleaved rounds (the subject order rotates), medians; the load average
before and after each binary's timings.

The monorepo's own commonware-codec is in the binary too: every storage copy
links it, as every crate in storage's graph does. It is never timed. Building
it runs its sandblaster verification (module mode), whose verdict cache the
monorepo's builds share.

History: this is the harness that measured what the removed optimizer
shipped (2026-10, `4a0e5a23fc`); the optimizer, its lowered copies and that
report are gone, and the subjects are now the original code and the
worktree's.
