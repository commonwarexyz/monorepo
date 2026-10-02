# The general optimizer corpus

Small sandblaster programs written the natural way, each showing one pattern
the optimizer must handle (docs/optimizer-design.md §2.3, §15;
docs/optimizer-plan.md O1). The plan's acceptance targets for them are in
plan §4.2.

| path | what |
| --- | --- |
| `dsl/mod.rs` | the corpus crate root: P1–P14 exactly as designed (research/optdesign/corpus/dsl/mod.rs), then the additions marker and one `pub mod` per later program |
| `dsl/p15_tree_dfs.rs` … `dsl/p20_sparse_mul.rs` | P15 threaded-cursor tree DFS, P16 batch of 20-deep hash paths, P17 GF(2^16) multiply by a constant over lo/hi blocks, P18 u64 carry chain, P20 sparse / constant-operand multiplication (P19 arrives with `u128`, O12) |
| `corpus.toml` | the manifest: per program its entry point and functions, pattern, expected route, rung and proof route, target ratio to ideal, milestone target, control flag, the recorded baseline, today's outcome per function, and its must-reject variant with a witness |
| `must_reject.rs` | one plausible but wrong candidate per program for its eventual route (same signature as the entry point) |
| `must_reject_controls.rs` | each of those variants with its bug fixed: the control that makes a rejection attributable |
| `conv_pairs.rs` | per program, a candidate today's route (tier-0 conversion) admits and its one-token mutation |
| `manifest.rs` | the `corpus.toml` reader shared by the tests |

**Frozen.** Everything above the `// ---- additions` line of `dsl/mod.rs`, every
program file and the three candidate files are frozen (gate G6,
`sandblaster/tools/gates/g6.sh`, with the harness's O1 emission and
hand-written references and the QMDB fixture). New programs are added as new
files with a `pub mod` line after the marker, then recorded with
`sandblaster/tools/gates/g6.sh --record` (which only appends).

**Development set.** The corpus is where the optimizer was developed: many
programs restate the benchmark targets (P4 the MMR peak walk, P5/P6 varints,
P7 QMDB's peak buffer, P16 Merkle paths, P17 Reed–Solomon's GF(2^16), P18 the
curve25519 carry chain), and features were built per program. Its results
are development-set numbers: regression evidence, never evidence of
generality, which only the held-out evaluation gives (fairness audit of
2026-10-02; DESIGN.md §8.2 item 11).

**Tests.**
- `tests/opt_explore.rs` (`corpus_outcomes_match_the_manifest`): the strict
  corpus build has no optimizer warning, and every function's outcome equals
  its `today.<function>` entry. A milestone that improves a program updates
  those entries deliberately.
- `tests/opt_reject.rs`: the must-reject **pairs**. A wrong candidate's
  rejection is evidence only if a correct candidate of the same shape (its
  control) is admitted — today's route refuses whole shapes (any relevant
  `match`, loops, helpers defined after the entry, closed forms it cannot
  convert) whether the candidate is right or wrong. For every pair, kernel
  evaluation shows the mutant differs from the program on its witness and
  the control agrees with it on its probes; then the controls and the
  mutants are proposed through `OptTestHooks`. A wrong candidate is never
  admitted (the source is printed; an error under strict). Each pair is
  classified and its reasons pinned in `corpus.toml`:
  - `corpus_conversion_pairs_are_attributable` (`conv_*`): 13 programs, those
    whose entry is `Specialized` today, have their control admitted and their
    one-token mutant rejected as not convertible — today's evidence. The other
    7 are pending O4 (no straight-line form exists).
    `conversion_mutants_are_one_token_mutations` checks the token diff.
  - `corpus_route_variants_are_rejected_and_classified` (`must_reject*`): all
    20 frozen variants are rejected, but so is every control, for the same
    reason; they are pending the milestone whose route admits their shape
    (P18's never can: it calls the entry itself).
  - `pair_classification_needs_an_admitted_control`: the classification
    refuses "rejected for a kernel reason" as evidence when the control is
    rejected too.
  A milestone whose route starts admitting a control updates that pair's
  status and reasons deliberately (the test fails until it does).

**Native harness.** `bench/opt-corpus` (checks first; current emission vs O1
emission vs ideal in one binary per code layout; aarch64 and x86_64 builds).
