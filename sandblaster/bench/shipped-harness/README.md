# Shipped-code harness

What sandblaster ships, timed against what Commonware had: the code
commonware-codec and commonware-storage actually compile from sandblaster's
emitted and lowered copies (codec's varint module, storage's MMR position
and peak arithmetic, and the first set of its Merkle proof verifier),
against the original Commonware functions, in one binary. The report is
`REPORT.md`.

```sh
cargo test -p commonware-codec; cargo test -p commonware-storage --lib   # verified builds
HEAVY=<admission wrapper> CARGO_TARGET_DIR=<dir> sandblaster/bench/shipped-harness/run.sh \
    --codec-out <codec OUT_DIR> --storage-out <storage OUT_DIR>          # [--rounds N (>= 21)]
```

## Pieces

| file | what |
| --- | --- |
| `run.sh` | the crate copies, the three binaries (layouts, overflow checks), the identity check, the differential check, the timings, the report |
| `prepare.py` | `gen/` (not committed): each subject's copies of commonware-codec and commonware-storage under their own package names — `orig` and `aa` from the merge base of the sandblaster branch (`git archive`, read-only), `shipped` from this worktree with the build's `OUT_DIR` files included where the crates include them (only the include paths change); checks this workspace's `[workspace.dependencies]` against the monorepo's |
| `subject/lib.rs`, `subject/probe.rs` | the ONE crate source of every subject: one out-of-line entry per measured function, over the subject's `codec` and `storage` |
| `subj_orig`, `subj_aa`, `subj_shipped` | the subjects: the original code, the same again (A/A control), the shipped code |
| `src/main.rs` | the binary: `check` (differential), `bench` (refuses < 21 rounds, runs `check` first) |
| `report.py` | `REPORT.md` from the result files |
| `results/` | the last run: `bench-*.json/md`, `samecode-*.json` and `samecode-blind-*.json` (the two identity checks), `check-*.txt`, `load-*.json`, `sources.txt` (the shipped files' SHA-256), logs |

## Method

The held-out harness's protocol (`sandblaster/bench/heldout-harness`, J11):
one workspace profile compiles every subject alike (opt-level 3, 16 codegen
units, no LTO, no target-cpu flag, no PGO; overflow checks on, Commonware's
release profile, and a second binary without them; a third with every
function and block aligned to 64 bytes); one crate source for every subject;
an A/A subject (the original code from its own copies: the noise floor); the
machine-code identity check (`samecode.py --family`, which follows calls into
each subject's own copies of the two crates, so code compiled from two copies
of the same source compares equal; the addresses of each copy's own panic
constants are not compared), and the same check with `--data-blind` (no data
address compared: code that differs only in which copy of a constant table
it reads compares equal); the differential check first; at least 21
interleaved rounds, medians; the load average before and after each binary's
timings.

`sandblaster/tools/gates/fair-baseline.sh --heldout` is written for the
held-out harness (its subject names) and refuses any `build-override`; this
workspace keeps the monorepo's (build scripts optimized: the one build script
is the monorepo codec's, shared by every subject, so no subject's code
depends on it). The rest of that rule (one crate source, an A/A subject, the
identity check, at least 21 rounds after the differential check) holds by
construction of `run.sh` and `src/main.rs`.

The monorepo's own commonware-codec is in the binary too: every storage copy
links it, as every crate in storage's graph does (cryptography's types
implement that codec's traits). It is never timed: the varint rows time the
codec copies. Building it runs its sandblaster verification (module mode),
whose verdict cache the monorepo's builds share.
