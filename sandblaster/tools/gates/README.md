# Optimizer fairness gates

The user's rule: the optimizer must not factor in its benchmark targets.
Optimizations are generic; the hot paths show where to look, but no rule,
constant or claim may be built around a benchmark. These gates make that
mechanical (fairness audit of 2026-10-02, guards list). None runs cargo
except through the test suite, and every one has a negative twin that must
fail.

| gate | where | checks | twin |
| --- | --- | --- | --- |
| G6 frozen inputs | `g6.sh`, `g6-selftest.sh`, `frozen.sha256` | the QMDB fixture's DSL sources (sums pinned in `g6.sh` itself); in `frozen.sha256`: the corpus (its frozen P1–P14 region, every program file, the must-reject candidates and conversion pairs), the corpus harness's frozen O1 emission and hand-written references (`bench/opt-corpus/ideal/src`), the QMDB fixture data (one `#tree` sum per directory), the QMDB profile/timing split (`fixtures/qmdb/splits`) and the held-out evaluation's files (`sandblaster/bench/heldout/`, recorded before anything is measured on them; not the generated `REPORT.md` that `run.sh` rewrites, nor Python caches). `--record` only appends new files and refuses when anything recorded changed | `g6-selftest.sh`: every kind of change is refused and `--record` cannot re-baseline it; the generated report is never frozen |
| name lint | `front/tests/fairness_lint.rs` | no identifier or string literal in `front/src/opt/**`, `driver/lowered.rs`, `lower.rs`, `rulegen/src`, `targets/src` names a benchmark target (comments and `#[cfg(test)]` stripped; a per-file allowlist with reasons, stale entries refused); the optimizer proper reads no validation row (`sha.*`, `varint.*`, …) | `the_lint_flags_its_twin` |
| constant pool | `front/tests/fairness_pool.rs` | Σ2's synthesis leaves, divisors, guard thresholds, template divisors and trace corners come from the loop (`opt::loopsum::pool`): only the width's `{0, 1, 2, W−1, W}` and `2^k−1, 2^k, 2^k+1` are fixed; and the consumers themselves (the synthesizer's enumeration, the `affine_atom` template) offer no divisor the pool lacks, so a fixed constant put back inside one of them is caught too (`the_synthesizer_and_the_template_use_only_the_pool`, with a loop shifting by 7 as the positive control) | `the_checks_reject_the_old_fixed_pools` |
| user alternatives | `front/tests/fairness_rewrites.rs`, `user-rewrites.toml` | no `#[rewrite]` lemma or `#[lift(opt)]` module in a monorepo DSL root (`<crate>/sandblaster/`, `sandblaster/fixtures/`) unless listed with an owner, a justification and `benchmark_excluded = true`; benchmark targets can never be listed | `the_scan_flags_its_twin` |
| attribution | `front/tests/lowered_use.rs`, `lift_opt.rs` | a user alternative is counted, named and reported apart from the optimizer's residuals (`LowerOrigin`), and `SANDBLASTER_EVAL_EXCLUDE_USER_REWRITES=1` builds the optimizer-only subject | the build-summary and report assertions |
| profile disjointness | `front/tests/fairness_profile.rs` | `PROFILE.json` declares its corpora; the QMDB profile is recorded on the profile half of `splits/` only, and `Profile::check_timed` refuses any timed input inside a profile corpus | the overlapping-split case |
| fair baseline | `fair-baseline.sh` (run by `bench/opt-corpus/run.sh`); `fair-baseline.sh --heldout` (run by `bench/heldout-harness/run.sh`) | a harness compiles every subject with one profile (no per-package override, no subject's own codegen flags), links them into one binary, and runs the machine-code identity check (a `python3 … samecode.py` command line; a comment or string naming it does not count); the held-out harness also: every subject compiles one crate source (the package feature selects the module), an A/A subject built like the rustc subject, the rustc subject's H1 is the G6-recorded frozen file, and the runner refuses fewer than 21 rounds and runs the differential check right before timing (in code: comments and messages do not count) | `fair-baseline.sh --selftest` (the corpus harness's twins and the held-out harness's: no A/A, an A/A of the optimized module, another crate source, a hand-trimmed copy, 3 rounds, timing before the check, no identity check; and the evasions the re-audit found: the identity check, the round floor or the check before timing present only in a comment or a message) |

```sh
sandblaster/tools/gates/g6.sh && sandblaster/tools/gates/g6-selftest.sh
sandblaster/tools/gates/fair-baseline.sh && sandblaster/tools/gates/fair-baseline.sh --heldout && sandblaster/tools/gates/fair-baseline.sh --selftest
$HEAVY cargo test --release -p sandblaster-front --test fairness_lint --test fairness_pool --test fairness_rewrites --test fairness_profile
```

**The review rule** (DESIGN.md, "Fairness"): every new rule, rung, template,
constant or threshold states its structural justification and its effect on
the held-out set; a change justified only by QMDB, the corpus, codec or
storage is not merged; and any "faster than rustc" statement cites the
held-out report.

## G6 provenance

`g6.sh`, `g6-selftest.sh` and `common.sh` are ported from the toolchain's
previous repository (`tools/gates/`), which pinned `qmdb/rustoleum/*` and
froze the corpus under `crates/rustoleum-front/`. Before recording
`frozen.sha256` here, every file it froze there was compared with its
monorepo copy: the corpus programs, must-reject candidates, conversion pairs
and the P1–P14 prefix are identical up to the rename `rustoleum` →
`sandblaster`, the O1 emission differs only in its `@generated` header path,
and `ideal/src/lib.rs` only in one doc path. The QMDB sources changed since
(the §15 spec work), so their sums are those of the monorepo's state when
the gate was ported. The QMDB benchmark baselines of the old repository
(`qmdb/bench/baselines`) did not move to the monorepo and are not frozen
here.

## Not covered yet

The held-out set is recorded: `sandblaster/bench/heldout/manifest.toml`,
`h1/` (blind programs) and `h2/` (rule-sampled monorepo functions, its rule
in `h2/RULE.md`), every file frozen by G6. Its harness is
`sandblaster/bench/heldout-harness` (plan step 8), checked by
`fair-baseline.sh --heldout`; its report is
`sandblaster/bench/heldout/REPORT.md`. The report is the harness's output,
rewritten by every run: G6 lists it as not recorded (a note, not a failure),
and it should stay unrecorded, or every later run would fail G6.

Not covered: the fair-baseline check is structural (it reads the harness's
sources). That both subjects get the same hand-written variants holds
because they compile one crate source; no check yet looks inside a subject
for a variant. The held-out set has none.
