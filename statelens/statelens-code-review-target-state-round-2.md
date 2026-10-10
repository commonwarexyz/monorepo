**Target-State Synthesis implementation review: round 2**

Review date: 2026-10-08. Initial review complete; reviewer validation of the subsequent fixes is recorded below.

Current reviewer verdict (2026-10-08): **12 of the initial 13 findings are verified FIXED; finding 5 remains PARTIALLY FIXED at medium severity**. The high dependency finding 2 is FIXED, closing original finding 4. Finding 5's residual lets a control use an incarnation that the parser explicitly disproves to claim another final state. Its author-marked FIXED status is superseded by the reviewer validation below. Subsequent selector-rename review found one low example/test-fixture discrepancy, finding 14 at the end of this report. No outstanding critical/high issue was established in either validation.

The initial review reported **1 high, 10 medium and 2 low**; no critical finding was established. The high finding was the remaining dependency-classification case of original finding 4. Its fix is now independently verified. Finding 6's triage correction to low is accepted, making the corrected historical ratings 1 high, 9 medium and 3 low. Initial counterexamples and snapshot identifiers below are retained as history, rather than claims about the fixed implementation.

Six fresh-context auditors reviewed runtime/helper semantics, reach verification and verdicts, synthesis lifecycle and guards, CLI/workflows, all prompts/cards/specification, and test soundness. Three further fresh evaluators assessed the dependency, runtime and control candidates. Two additional fresh audits then found no further critical/high issue beyond finding 2, satisfying the requested stopping rule. Only review reports were edited.

The working tree is uncommitted against HEAD `8a0d2cef732b2607e8c742fa71ee438a97e42467`. The initial script SHA-256 is `7fcc830485f4abd98141f612e775f19add902a589921957e12f548f2dc2549b8`; tests are `7878d7e1e05bbcab5494ddac3247c998038986e6322084e0ca3c37330ae2f435`. Locations use paths and symbols rather than unpinned source line numbers.

**Reviewer validation of the fixes, 2026-10-08**

Five fresh-context auditors assessed lifecycle/dependency invalidation, control identity and replay boundaries, process ownership, workflow/restoration, and prompts/specification. A sixth fresh-context evaluator independently tested finding 5's remaining identity case. The review checked implementation, regressions, original fixtures where applicable, positive controls and documentation. Only the three review reports were edited; implementation, tests, prompts, cards and plan remained unchanged.

| Finding | Criticality | Reviewer disposition | Verification |
| --- | --- | --- | --- |
| 1 | medium | FIXED | The rollback obligation precedes report restatement and survives until the current report is committed. Original scalar fixture passes 3/3; independent real SIGKILL, post-report OSError and repeated revalidation interruptions recover source/report consistency while retaining evidence. |
| 2 | high | FIXED | Own modules are shared. Actual compiled helper fixtures cover explicit calls, implicit inherent methods and implicit trait dependencies. A replacement that worsens another standing scaffold is rolled back, and retained reports agree with fresh execution. |
| 3 | medium | FIXED | Final builds run even when no card changes. Original known-unbuildable regression and an unselected unbuildable sibling both exit 2 without handover. |
| 4 | medium | FIXED | Additional withholding, absent later events and synthesized `(no line)` stages are rejected. A later missed outcome remains accepted. |
| 5 | medium | PARTIALLY FIXED | Missing/unknown/key/`as` conflicts are fixed. Nonexistent, future and superseded incarnations are rejected by `reach_replay` but still accepted as a distinguishing identity by `control_status`; see finding 5 below. |
| 6 | low | FIXED | An incomplete first invocation remains NO REPORT; a second cannot supply its completion. Duplicate successful callbacks and prefix/continuation panics retain the correct report and failure phase. Raw replay output was already preserved. |
| 7 | medium | FIXED | Real SIGINT, SIGTERM and SIGHUP through the registered handlers each return 130. Before sealing, preserving or restoring, the direct child is killed and reaped and its descendant is stopped. Restored source stays unchanged beyond both write deadlines. |
| 8 | medium | FIXED | After the leader exits, a real descendant holding stdout is killed by the 0.2 s deadline; the call returns None in 0.212 s. Normal completion, environment, stdin and exceptional output handling retain their contracts. |
| 9 | medium | FIXED | Simplex guidance and SPEC copies preserve `should_bound_standard_liveness`, omission-victim exclusion and recovery draining. Verified against the referenced base code and rendered prompts. |
| 10 | medium | FIXED | Revalidation refreshes current reproduction commands when a failure moves to control, including its environment and input. If the failure disappears, the placeholder returns without the control variable. |
| 11 | low | FIXED | Printed TSS commands execute with space/apostrophe paths and preserve argument boundaries. Plain-path output and placeholder substitution also pass. |
| 12 | low | FIXED | Untracked and merely staged test sources abort before agent dispatch. A modified tracked test still dispatches with its provenance warning. |
| 13 | medium | FIXED | Restoring a replaced file removes its symlink first and preserves the sibling. Root/nested/dangling parent links are skipped with warnings without writing into their targets. |

Triage corrections accepted: finding 2's old exit-0 fixture expectation is superseded by rollback of the breaking card. A dependent that temporarily stops building is recorded NOT BUILT and does not retain stale REACHED. Finding 6 did not lose the raw log, does not require a new helper delimiter, and needs invocation-dependent behavior for the false completion; low severity is appropriate. Timed commands already killed their group on interruption before finding 7's fix, but did not reap the direct child. Finding 8's practical scope is narrower because only the scaffold replay is timed; no supported protocol target creating descendants was established. Its timeout-contract defect is nevertheless fixed.

Acknowledged limits remain separate from finding 5: the PID-reuse window, Phase-1 comment-source provenance, older `Campaign.handover` quoting, and no automatic replay of a previously NOT BUILT scaffold that a later card makes buildable. These do not invalidate the verified fixes to their stated causes. The last case conservatively withholds certification until `--redo`. Parent-directory symlinks are not repaired, and newly added dangling/directory links omitted by `scope_files` can survive restoration; the checked fix prevents the reported write-through corruption.

Current checks, with implementation and tests unchanged throughout:

- `just check-scripts`: **451 tests passed**; [log](/private/tmp/tss-r2-fixes-check-scripts.log).
- `just check-prompts`: **0 problems**; [log](/private/tmp/tss-r2-fixes-check-prompts.log).
- `just check-invariants`: **68 files, 0 problems**; [log](/private/tmp/tss-r2-fixes-check-invariants.log).
- `git diff --check`: passed. Both plan copies are byte-identical.

Focused evidence: [lifecycle validation](/private/tmp/tss-r2-lifecycle-validation-hxRdseCS/validate.py) (76 repository checks, 8 independent checks, 3 original scalar checks and the original unbuildable regression); [control/replay results](/private/tmp/tss-r2-fresh-controls-validation-cdrndd5y/summary.json) (16 scalar/log checks and 10 focused regressions); [process fixture](/private/tmp/tss_r2_processes_validation.py) and [results](/private/tmp/tss_r2_processes_validation_results.md) (3 checks, including all three signals); [workflow fixture](/private/tmp/tss-r2-independent-workflows-fix-validation.py) (12 repository, 5 original and 7 independent checks). Prompt validation includes 24 focused repository checks, four card lints, eight prompt renders, exact runtime appendix copies and source-contract inspection. Finding 5 has an additional independent evaluator and positive controls linked below. Counts overlap with the full suite and are not additive.

The [pinned snapshot manifest](/private/tmp/tss-r2-fix-validation-pvonfib_/manifest.json) covers 41 files and recorded no changes during copying. All non-report entries still match at completion. These identifiers distinguish this validation from the initial review retained below:

| Current checked file | SHA-256 |
| --- | --- |
| `statelens/scripts/statelens.py` | `6d1f251f73fb87b70ebe9e518e8dd17efab2c4dd99ead1396f7d630df1596d7b` |
| `statelens/scripts/test_statelens.py` | `c8844d85b77108ca5da923f28c9b04e02e005519fcbac7404ba0ba9c1aea0004` |
| `statelens/runtime/target_states.rs` | `551ed5251f6429cbc1c3d4cba4b675d2c70d7047983ccf7260a3c2f22c23f84f` |
| `statelens/runtime/statelens.rs` | `72f549efe22a41b2abf2238f83bb6a9e135ae997876da50e5f80f70fe006d26a` |
| `statelens/prompts/subsystems/simplex-synthesize.md` | `2f884d4743d364b0f507feb914506d3e9af915fee89c865677e968a5eccb0919` |
| `statelens/docs/SPEC.md` | `ca02d5b47f0c0df8cabf4a02fe0ede71db800593090af3371be2b2e94ea14769` |
| `statelens/docs/PRD.md` | `2c0b9a85e5f50ad962cda000a1b2afc0cc6022fdca604e9237c86ef4eb4fa2b7` |
| `statelens/statelens-tss-plan.md` | `53925b321c7de270793b9538d8feb9f57532bdde983ead2c79450030f2063db6` |

Validation uses harmless scalar fixtures, actual Rust/helper compilation where stated, real owned subprocesses, temporary Git trees and mocked Cargo/agent dispatch. No generated Simplex/Marshal protocol campaign was executed, so these results establish fix behavior at the checked boundaries rather than end-to-end protocol correctness.

**1. Criticality: medium - Rolling back an interrupted card can retain an earlier report's improved verdict. SHOULD FIX.**

Status: FIXED (2026-10-08). In `statelens/scripts/statelens.py`, `Synthesis.revalidate` now records `a rollback` of the card in `revalidation.json` (new `UNDO_TAGS` entry, `after-rollback/`) before the first `restate`, and `Synthesis.synthesize` deletes the record only after the card's report is written, so an interrupt, another error or `recover` after a kill keeps the obligation and the next synthesis revalidates every scaffold before any card (SPEC 18.6.2 and 18.11, PRD R-TS-SYN-1). Regression tests `test_a_card_interrupted_after_its_revalidation_rewrote_a_report_owes_it` and `test_a_card_killed_after_its_revalidation_rewrote_a_report_owes_it` (both fail without the fix) and the control `test_a_card_interrupted_before_its_revalidation_rewrote_a_report_owes_nothing` are in `Synthesize`; the reviewer's scalar fixture, pointed at the fixed tree, passes 3/3 with the resume ending PARTIAL 1/4, and `just check-scripts` passes (434 tests).

Location: `statelens/scripts/statelens.py`, `Synthesis.revalidate`, `restate`, `finish`, `synthesize`, `recover`, and `load_standing`.

`revalidate` successfully checks earlier scaffolds with the current card's shared edits and publishes their resulting verdicts through `restate`. Before the current card's report is committed, `finish` performs further snapshot, diff and report writes. An interruption in that interval enters the ordinary card rollback: `synthesize` restores source `S0` and removes the pending snapshot. The earlier reports are neither restored nor made subject to durable revalidation.

Consequently, an earlier scaffold that improved only because of the rolled-back shared edit can retain `REACHED` after that edit is gone. A subsequent own-file-only replacement does not revalidate earlier scaffolds; the final build verifies compilation only. The resumed invocation can therefore return success with an obsolete reach verdict.

Independent evidence uses a harmless Rust scalar function that compiles in both states. Its value drives the existing mocked reach-output fixture:

| Boundary | Source scalar | Earlier report | Exit |
| --- | --- | --- | --- |
| Initial accepted scaffold | 0 | PARTIAL 1/4 | 0 |
| SIGINT after report restatement and completed rollback | 0 | REACHED 4/4 | 130 |
| Successful own-file-only resume | 0 | REACHED 4/4 | 0 |

No pending snapshot or revalidation journal remains after rollback. Adjacent controls pass: interruption before restatement preserves PARTIAL; uninterrupted completion retains scalar 1 and REACHED. The original signature/shared-edit rejection and durable-undo controls also pass.

This differs from original finding 4 and V1: revalidation succeeds, but publishing its results is not coordinated with source rollback. The additional requirements of an improved earlier verdict and an interruption during final bookkeeping support medium severity. The evidence establishes orchestration behavior, not a real Simplex or Marshal protocol failure.

Suggested fix: include affected reports in the recoverable card transaction and restore them with `S0`, preserving replay evidence, or durably require revalidation before publishing changed reports and retain that obligation through ordinary rollback and pending recovery. Moving a single report write does not make all source/report updates atomic.

Evidence: [independent scalar fixture](/private/tmp/tss-rollback-scope-eval-20261008-tnbu6bc_/scalar-boundary.py), [captured result](/private/tmp/tss-rollback-scope-eval-20261008-tnbu6bc_/scalar-boundary-captured.log), [seven passing original-cause controls](/private/tmp/tss-rollback-scope-eval-20261008-tnbu6bc_/original-cause-controls.log), and [separate earlier reproduction](/private/tmp/tss-durable-undo-eval-20261008-9egxqdgy/finish-rollback-boundary.log).

**2. Criticality: high - A scaffold's own module can invalidate a dependent scaffold without revalidation. MUST FIX.**

Status: FIXED (2026-10-08). `Synthesis.shared_paths` in `statelens/scripts/statelens.py` now exempts only the thin target, the package manifest, `target_states/mod.rs` and `Cargo.lock` (`own = {self.manifest, self.mod_rs, "Cargo.lock"}`), so a card's own module is shared code, every kept version revalidates every other standing scaffold, and every undo (`--redo`, last check, rollback) owes one through the existing `undo` -> `owe` path, with `revalidate` naming the changed paths on the console. Regression tests `Synthesize.test_a_redo_whose_module_changes_a_helper_a_sibling_uses_revalidates_it` (TS-0005 calls `super::ts0004::limit()`; a `--redo` of TS-0004 replays TS-0005 after the undo and after the new version, which is then rolled back `NOT BUILT (breaks TS-0005)`, exit 3) and `test_a_card_that_touches_only_its_own_files_revalidates_the_earlier_scaffolds_too` fail without the fix; the existing expectations were updated, and SPEC 18.6.2, 18.11, AC-24, PRD R-TS-SYN-1 and the README give the public-sibling reason. Two corrections to this finding: once the exemption is dropped, the SPEC's rollback rule makes the mocked lifecycle fixture end with A rolled back rather than kept (its `result == 0` is a stale expectation), and in the real-helper fixture B is recorded `NOT BUILT (no longer builds)` after A's undo and is not replayed when A's new module makes it build again, the limitation SPEC 18.11 documents; no false REACHED remains in either case, and removals are already covered because the module path is in the owed record.

Location: `statelens/scripts/statelens.py`, `Synthesis.shared_paths`, `undo`, `owe`, `revalidate`, and `last_build`; SPEC 18.6.2's own-file exemption.

`shared_paths` unconditionally excludes the current card's `target_states/tsNNNN.rs`. Generated scaffolds are public sibling modules in the same crate, and the edit contract does not prohibit one from calling another's public setup or observation helper. Changing such a helper is therefore treated as private even when another scaffold depends on it.

Redoing A can preserve its helper's signature while changing the state B constructs. Neither the undo nor the replacement schedules B for replay. The final build succeeds because the API still compiles, and successful synthesis retains B's obsolete `REACHED` report.

Independent validation compiled generated sibling modules and the unchanged actual helper, with scalar state and a clock/trace shim. Initially B reported `REACHED 2/2`. Redo changed A's `initial_value()` from 1 to 0 and returned 0. B was rebuilt but not replayed; its stored report remained `REACHED 2/2`, while a fresh execution of that rebuilt binary through `reach_verdict` returned `PARTIAL 1/2`. Four adjacent controls passed, including an independent B without the sibling dependency.

This requires no interruption or forged evidence. It leaves accepted reach certification false after an ordinary successful operation, supporting high severity. The current specification encodes the same unsupported independence assumption.

Suggested fix: treat own-module changes/removals as potentially shared and revalidate dependents, conservatively revalidate earlier scaffolds, or mechanically establish compilation independence before applying the exemption. Include removals in durable undo obligations.

Evidence: [actual-helper dependency fixture](/private/tmp/tss_r2_dependency_actual_helper.py), `Dependency.test_dependent_report_tracks_real_helper_replay`, and [independent lifecycle fixture](/private/tmp/tss_r2_lifecycle_20261008.py), `Lifecycle.test_redo_rechecks_a_scaffold_importing_an_own_module_helper`. Cargo/agent dispatch is substituted; compilation, generated helper output and verdict parsing are real. No protocol behavior is claimed.

**3. Criticality: medium - An unchanged invocation can successfully hand over a known-unbuildable scaffold. SHOULD FIX.**

Status: FIXED (2026-10-08). `Synthesis.run_cards` now calls `last_build` unconditionally (the `if outcomes:` shortcut and its comment are gone), so every synthesis, also one that synthesized no card, builds every scaffold in the package and exits 2 with the last-check error while one does not build, printing no run line for it. `Synthesize.test_the_last_check_builds_every_scaffold` is now the no-card scenario (a scaffold that stops compiling between syntheses; the run that skips every card builds it, exits 2, prints no run line) and the tail of `test_a_redo_that_breaks_a_kept_scaffold_records_it_not_built` expects the unchanged run to exit 2 again with the `load_standing` warning; both fail without the fix, the reviewer's `test_skipped_known_unbuildable_scaffold_still_fails` passes against the current tree, and SPEC 18.6.2 Last check says the build happens on every run.

Location: `statelens/scripts/statelens.py`, `Synthesis.run_cards`, `load_standing`, `last_build`, and `select_scaffolds`.

After redo removes a required shared accessor, an earlier scaffold can be recorded `NOT BUILT (no longer builds)` and synthesis correctly exits 2. The next unchanged invocation skips every reported card. With `outcomes` empty, `run_cards` skips `last_build`; selection uses thin-target presence and prints run commands for the still-unbuildable target, returning 0.

The expected-safe fixture confirms zero builds on the second invocation and successful handover of both targets. The repository test `Synthesize.test_a_redo_that_breaks_a_kept_scaffold_records_it_not_built` currently expects this erroneous subsequent success. Unlike original finding 20, this is a retained scaffold with an explicit failed revalidation report, rather than abandoned attempt files.

Suggested fix: verify retained builds before successful handover even when every card was skipped, or refuse failed-build statuses until a successful rebuild clears them.

Evidence: [lifecycle fixture](/private/tmp/tss_r2_lifecycle_20261008.py), `Lifecycle.test_skipped_known_unbuildable_scaffold_still_fails`. Builds and reach results are harmless scalar mocks.

**4. Criticality: medium - A control can omit additional events and still certify reach. SHOULD FIX.**

Status: FIXED (2026-10-08). `control_status` in `statelens/scripts/statelens.py` now returns `vacuous` for every stage strictly between Ek and En that has no line in the control run (absent, or the `(no line)` entry `reach_replay` synthesizes: `E{j} has no line in the control run`) or is withheld too (`E{j} is withheld in the control run too`); stages before Ek were already rejected by the existing vacuous `binds other values` check, so the gap was the stages after Ek only, and a later `missed` stays an outcome. Regression test `ReachCheck.test_a_control_that_omits_a_later_event_too` (the helper's additional-withheld and absent logs give `UNVERIFIED 4/4` with the control feedback; a later `missed` stays `REACHED 4/4`) fails without the fix (`'ok' != 'vacuous'`), the reviewer's two checks pass against the current tree, and SPEC 18.8 and PRD R-TS-SYN-5 list the clause.

Location: `statelens/scripts/statelens.py`, `control_status` and `reach_replay`.

After checking the selected withheld event, `control_status` checks earlier stages and the final stage without requiring outcomes for every later event. It accepts another later `withheld`, or an absent later outcome, when handoff, reach and done lines exist. That additional omission can independently explain the final miss, so the control does not establish causality for the named event.

The actual helper sequence `withheld(1); missed(2, ...); withheld(3); handoff(|| None); done()` was accepted as `control=ok`, yielding `REACHED 4/4`. Omitting stage 3 entirely had the same result. This remains after original finding 6's completion-line checks were fixed.

Suggested fix: require an outcome for every later event and reject withholding anywhere except the selected event. A prior miss must not excuse missing subsequent control evidence.

Evidence: [scalar helper fixture](/private/tmp/tss-r2-verdicts-helper.rs), [additional-withheld output](/private/tmp/tss-r2-verdicts-additional.log), and [absent-event output](/private/tmp/tss-r2-verdicts-absent.log).

**5. Criticality: medium - An incomplete control identity is accepted as evidence of another final state. SHOULD FIX.**

Status: PARTIALLY FIXED (reviewer validation, 2026-10-08). Missing, `?`, key-conflicting and present-`as`-source conflicting bindings are fixed. Two fresh-context reviewers independently confirmed that `control_status` still uses an incarnation contradicted by the parser's own restart metadata as evidence of another final state. This is a residual of finding 5, not a new numbered finding.

Verified fix history: the weak condition of `control_status` in `statelens/scripts/statelens.py` no longer compares the raw `stage_values`: an entity the control's En witness leaves out of `bind=`, binds to `?`, or binds to a value its own key pairs or the control stage its `as Ej` cites contradict is no evidence of another state (`apart`), so such a control is `weak` (UNVERIFIED k/n with the weak feedback, the witness rejection tolerated as SPEC 18.8 prescribes), while a genuine different-identity control (`d=cd` in bind and key) stays REACHED. Regression tests `ReachCheck.test_a_control_witness_that_leaves_an_entity_unbound` and `test_a_control_bind_its_own_evidence_contradicts_tells_nothing_apart` pass. These changes fix the reported missing/unknown/key/`as` cases, but do not establish that every concrete incarnation difference is valid.

Remaining medium defect: `reach_replay` rejects an incarnation that does not exist, starts after the evidence position, or has been superseded for the bound replica. `control_status` nevertheless compares that concrete value with the canonical incarnation; its `apart` result bypasses the weak-control rejection even though the final witness is `unverifiable (witness rejected: incarnation)`.

Independent three-stage scalar checks compiled the unchanged actual helper and runtime. The helper emitted all entries and restart positions; the fixture did not fabricate log lines:

| Control final incarnation | Parser result | Overall verdict |
| --- | --- | --- |
| Same valid `inc1` | held | UNVERIFIED 3/3 (weak) |
| Real different `inc3`, backed by a restart | held | REACHED 3/3 |
| Nonexistent `inc60000` | witness rejected: incarnation | REACHED 3/3 |
| `inc4` starts after stamped evidence at seq 3 | witness rejected: incarnation | REACHED 3/3 |
| Superseded `inc3`, latest applicable restart at seq 4 | witness rejected: incarnation | REACHED 3/3 |

A separate four-stage actual-helper fixture independently returns REACHED 4/4 for nonexistent `inc999`, while its same-incarnation control is weak and its real alternative incarnation is accepted. These are mechanically disproved identities, distinct from the documented limitation of values that nothing confirms or contradicts. Thus the negative control still does not demonstrate that withholding the event prevents the canonical final state.

Required remaining fix: exclude contradicted incarnation bindings from `apart`, checking existence, evidence timing and the applicable latest restart independently of earlier witness-rejection rules. Do not blanket-reject every unverified control witness: a genuine different exact-key identity must remain usable when its `as` source was deliberately withheld. The independent positive control for that expected `as` rejection still returns REACHED.

Current evidence: [independent assessment and hashes](/private/var/folders/j2/7vcvwv0577n4086kbwrrgkkc0000gn/T/tss-r2-identity-independent-ef0sfon0/assessment.json), [three-stage scalar fixture](/private/var/folders/j2/7vcvwv0577n4086kbwrrgkkc0000gn/T/tss-r2-identity-independent-ef0sfon0/identity.rs), [results](/private/var/folders/j2/7vcvwv0577n4086kbwrrgkkc0000gn/T/tss-r2-identity-independent-ef0sfon0/summary.json), [independent four-stage results](/private/tmp/tss-r2-incarnation-controls-validation-m7nvzt8i/summary.json), and [expected-safe check](/private/tmp/tss-r2-incarnation-controls-validation-m7nvzt8i/expected-safe.log). Script SHA-256: `6d1f251f73fb87b70ebe9e518e8dd17efab2c4dd99ead1396f7d630df1596d7b`; tests: `c8844d85b77108ca5da923f28c9b04e02e005519fcbac7404ba0ba9c1aea0004`.

Location: `statelens/scripts/statelens.py`, `control_status` and its final `stage_values` comparison.

A control's final exact witness can cite the same entity key as the canonical run while omitting an entity from `bind=`, or binding it to `?`. The verifier rejects that witness, but the incomplete binding differs from the canonical binding and is then treated as evidence of a different entity. The control becomes `ok` rather than unverifiable.

Actual-helper output still named `certify[R=1,v=2,d=ab]=pending` while omitting `d` from the binding. Its final stage became `unverifiable (witness rejected: bind)`, yet the overall verdict was `REACHED 4/4`. A `d=?` variant also passed. This undermines the control's exclusion of weak identity-only witnesses.

Suggested fix: require concrete, validated identity evidence before accepting a different-entity comparison. Narrow tolerated witness rejection to dependencies genuinely absent because of the selected withholding.

Evidence: [unbound-control helper fixture](/private/tmp/tss-r2-verdicts-unbound-control.rs) and [output](/private/tmp/tss-r2-verdicts-unbound-control.log).

**6. Criticality: low - Replay filtering can borrow completion from a later input invocation. SHOULD FIX.**

Status: FIXED (2026-10-08). `first_run` in `statelens/scripts/statelens.py` now keeps one run of the input instead of cutting at the first `done`: a run opens with the `phase prefix` line `Stages::new` prints unless a `panic` line of its run precedes it (the hook reprints the phase after `panic`), and the run kept is the one that printed a `panic` line, else the first, so a later run never completes an earlier one's report and a later run's failure is read in its own phase; no Rust change was needed. Regression tests `ReachCheck.test_a_replay_log_holds_one_run_of_the_input` (incomplete first plus complete second gives `NO REPORT`; a passing run printed twice gives one `done`, `REACHED 4/4`) and `test_a_panic_in_the_second_run_is_read_in_its_own_phase` fail without the fix, the reviewer's two checks pass, and SPEC 18.8 replaced the first-`done` rule. Two points of the finding did not hold: the raw output was already preserved (`Synthesis.replay` writes the whole `replay.log`; `first_run` filters only the returned text) and no explicit delimiter was needed in the helper; since the completion case also needs run-dependent scaffold behavior, as the finding concedes, the severity is low rather than medium.

Location: `statelens/scripts/statelens.py`, `first_run`, `Synthesis.replay`, and `replay_failure`.

`first_run` stops retaining helper lines after the first `done`, rather than at the next invocation. If one invocation returns before `done` and another completes, the filtered log combines them. The later invocation supplies the first one's missing completion and can turn an incomplete report into `REACHED`.

The helper fixture resets per-input state between two invocations and reaches handoff in both, while the first omits `done`. The first segment alone yields `NO REPORT`; the combined filtered output yields `REACHED 4/4`. The installed `libfuzzer-sys` 0.4.13 source confirms that individual-file replay can execute its callback again for leak checking, subject to allocation imbalance and LSan availability. This counterexample requires invocation-dependent scaffold behavior, which the fixture deliberately supplies; it does not establish that a normal deterministic scaffold takes this path. No actual libFuzzer replay was executed.

SPEC 18.8 currently prescribes the same first-`done` algorithm. This is a boundary-design gap against completion/oracle requirements, requiring a specification correction alongside the implementation.

The same filter also loses a later invocation's prefix phase when that invocation panics, attributing the retained failure to the first invocation's continuation. The crash verdict and location remain present.

Suggested fix: delimit input invocations explicitly; a later invocation must not complete an earlier report. Preserve raw output and associate crash-phase evidence with the failing invocation.

Evidence: [incomplete-first fixture](/private/tmp/tss-r2-verdicts-incomplete-first.rs) and [output](/private/tmp/tss-r2-verdicts-incomplete-first.log); [second-invocation failure fixture](/private/tmp/tss-r2-verdicts-second-pass.rs) and [output](/private/tmp/tss-r2-verdicts-second-pass.log).

**7. Criticality: medium - An interrupted agent can keep writing after synthesis restores the tree. SHOULD FIX.**

Status: FIXED (2026-10-08). `run_logged` in `statelens/scripts/statelens.py` now starts every command in its own process group (`start_new_session=True` unconditionally) and, on `KeyboardInterrupt` or any other exception, SIGKILLs the group and reaps the leader (`kill()`, `process.wait()`) before the exception reaches `run_agent`'s seal and `synthesize`'s preserve and restore; the new module-level `interrupt` handler maps SIGTERM and SIGHUP to `KeyboardInterrupt` under `__main__`, so a supervisor's kill or a closed terminal takes the same path instead of orphaning the agent in its new session. Regression test `LoggedRuns.test_an_interrupt_kills_the_command_and_what_it_started` (a child that ignores SIGINT must never write after the interrupt) fails without the fix, both reviewer fixtures pass against the current tree (`final='restored'`; `restored_after_agent_exits: true`, exit 130), and SPEC 18.6.1, 18.6.2, 18.11, PRD R-TS-SYN-3 and the README describe the kill-first order. One precision: for timed replays the group was already killed on interrupt, so only the reap was missing there.

Location: `statelens/scripts/statelens.py`, `run_logged`, `Synthesis.run_agent`, and `synthesize`.

For commands without a timeout, `run_logged` propagates interruption without terminating and waiting for the child process tree. Synthesis then seals references, restores `S0` and deletes `pending/` while the agent can still write. A process handling SIGINT or finishing another task can modify the tree after the restoration that the script reports as complete.

A real process-group SIGINT produced exit 130, immediate restoration and no pending snapshot. One second later the harmless agent appended a scalar-file comment, leaving that restored source modified. This directly exercises the synthesis lifecycle rather than just a standalone subprocess helper.

Suggested fix: own process groups for untimed commands too, and terminate/reap them before propagating interruption and performing rollback or reference sealing.

Evidence: [synthesis interruption fixture](/private/tmp/tss_r2_synthesis_interrupt_check.py); [isolated process fixture](/private/tmp/tss_r2_interrupt_check.py). No production or protocol process was involved.

**8. Criticality: medium - A timeout can stop enforcing its deadline when the process leader exits. SHOULD FIX.**

Status: FIXED (2026-10-08). The `kill` callback of `run_logged` in `statelens/scripts/statelens.py` lost its `if process.poll() is None` guard: the timer always sets `killed` and then runs `os.killpg(process.pid, SIGKILL)` under `suppress(OSError)`, so the deadline covers a descendant that outlives the leader holding the output pipe. Regression test `LoggedRuns.test_a_timeout_kills_a_child_that_outlives_the_command` (the leader exits after spawning a 60 s sleeper that inherits stdout; `run_timed(script, 1)` returns code None in about 1 s) fails without the fix (code 0 after 60 s), the reviewer's fixture gives `code=None, elapsed=0.16`, and SPEC 18.8 says the kill applies whether or not the replay's own process still runs. The only timed command is the scaffold binary of `Synthesis.replay`, which is not known to leave such descendants, so the practical severity was lower than stated; the pre-existing sub-millisecond window between a command's natural exit and `timer.cancel()`, which the guard did not close either, is left as is.

Location: `statelens/scripts/statelens.py`, `run_logged` and its `kill` callback.

The timeout kills the process group only while `process.poll()` says the leader is running. If the leader exits and a descendant retains stdout, output draining still blocks, but the timer does not kill that descendant. The command can exceed its deadline or wait indefinitely.

A 0.15-second deadline returned success after approximately 0.878 seconds because the pipe-holding child ran to completion. An existing protocol target creating such descendants was not established; the defect is in the command runner's deadline contract.

Suggested fix: enforce the deadline over the process group and output-draining lifetime independently of the leader's status.

Evidence: [workflow fixture](/private/tmp/tss_r2_workflows_checks.py), `WorkflowReview.test_timeout_bounds_pipe_inheriting_child_after_parent_exits`.

**9. Criticality: medium - Simplex prompt liveness rules omit the base's applicability guard and victim exclusion. SHOULD FIX.**

Status: FIXED (2026-10-08). The "Progress and deadline" bullet of `statelens/prompts/subsystems/simplex-synthesize.md` now says that `run_standard_once` and `run_audited_standard_once_with` wait only when `should_bound_standard_liveness(&input)` holds (a `Connected` partition, a valid configuration and `BlockFilterChoice::None`), otherwise sleep `MAX_SLEEP_DURATION` and assert no liveness, so FaultyNet, whose partition `fuzz` always sets to `Adaptive`, never waits, and that the audited driver leaves the notarize-omission victim out of the wait and keeps its post-invariant recovery-drain check (`unresolved_finalize_recoveries`, `check_finalize_recoveries_drained`); every claim was re-verified against `consensus/fuzz/simplex/src/lib.rs` and `consensus/fuzz/core/src/utils.rs` at HEAD, and the rest of the bullet was correct and is unchanged. The SPEC section 13 copy was regenerated with `just check-prompts --write` and the 18.7 paraphrase hand-edited to the same rule; `lint-prompts` reports 0 problems. A prose rule has no regression test; no code or test changed.

Location: `statelens/prompts/subsystems/simplex-synthesize.md`, "Progress and deadline"; SPEC 18.7 and its prompt copy. Source: `consensus/fuzz/simplex/src/lib.rs::{should_bound_standard_liveness,run_standard_once,run_audited_standard_once_with,fuzz,fuzz_audit_notarize_omission}` at commit `8a0d2cef732b2607e8c742fa71ee438a97e42467`.

The prompt says Standard and audited Standard wait for every reporter and directs Shape B to rebase that wait. The actual base waits only for connected partitions, valid configurations and absence of a block filter. `FaultyNet` uses an adaptive partition and has no such wait. The audited finalizer loop also skips `omitted_validator`, which instead has its separate recovery-drain check.

Following the explicit subsystem instruction can add liveness obligations that the base deliberately excludes, producing false finding candidates under legitimate fault schedules. The generic instruction to preserve existing oracles does not resolve this conflicting concrete rule.

Suggested fix: retain the applicability predicate, omission-victim exclusion and recovery-drain check explicitly; rebase only existing waits for their existing reporter set. Update both SPEC copies.

Evidence: [all-prompt review inventory and hashes](/private/tmp/tss-r2-prompt-review-my9q9oy5/evidence.json). All 23 prompt copies lint clean, showing that copy consistency alone does not verify the source contract. No generated protocol failure was claimed.

**10. Criticality: medium - Revalidation retains obsolete failure reproduction commands. SHOULD FIX.**

Status: FIXED (2026-10-08). `Synthesis.restate` in `statelens/scripts/statelens.py`, given a revalidation result, appends the crash line (`crash_text`, factored out of `write_report`) to the revalidation section for a CRASH with an attribution and rewrites the report's `## Run and replay` block (`REPORT_RUN_BLOCK`) from the latest check through `run_lines`, so the replay line carries `STATELENS_REACH_CONTROL=1` and the current crash file for a failure in the control replay, or the `<crash file>` placeholder when the latest check has none; the top `- Crash:` line stays the synthesis-time record. Regression tests `Synthesize.test_a_revalidation_rewrites_the_run_and_replay_lines_for_its_failure` (a failure migrating from the canonical to the control replay in a Finish revalidation) and `test_a_revalidation_that_loses_the_failure_restores_the_placeholder` (a `--redo` revalidation with `Before: CRASH ... Now: REACHED 4/4`) fail without the fix, the reviewer's fixture passes 2/2, and SPEC 18.6.2 Finish and Outputs and PRD R-TS-SYN-7 now say the lines are those of the latest check.

Location: `statelens/scripts/statelens.py`, `Synthesis.restate`, `stands_worse`, and report Run/replay generation.

`restate` updates Verdict and appends revalidation results while retaining the original Crash and Run/replay sections. CRASH-to-CRASH is accepted, so a failure can move from canonical to control without rejection. The report then names the new control panic while its commands still omit `STATELENS_REACH_CONTROL=1` and point to the old canonical input.

The safe workflow fixture returned success after that migration, but the expected-correct command assertion failed. Current reproduction guidance therefore does not match the newly kept tree and failure.

Suggested fix: generate current crash details and commands from the revalidation result and directory, or clearly mark earlier commands as history and provide executable commands for each new failure.

Evidence: [revalidation report fixture](/private/tmp/tss-r2-crosscutting-revalidation-report.py) and [log](/private/tmp/tss-r2-crosscutting-revalidation-report.log). Both build/replay workflows are mocked scalar cases.

**11. Criticality: low - Handover commands fail for checkout paths containing spaces. SHOULD FIX.**

Status: FIXED (2026-10-08). `Synthesis.run_lines` in `statelens/scripts/statelens.py` quotes the checkout (`cd {shlex.quote(str(self.repo / SL))} && `) and the crash file with `shlex.quote`, quoting the artifacts directory and appending `/<crash file>` unquoted so the documented placeholder form is unchanged and a space-free checkout renders byte-identically; `shlex.join` does not apply, since the line is `cd X && ENV=... just run ...`, and the rest of the chain (both justfiles use `"$@"`) already preserves a quoted argument. Regression tests in the new class `HandoverLines` (`test_a_checkout_with_a_space_is_quoted_and_the_placeholder_is_not`; `test_the_lines_run_as_printed_from_a_checkout_with_a_space`, which runs the lines through `bash -c` with a stub `just` under a directory whose name holds a space; and the control `test_a_space_free_checkout_renders_unquoted`) fail without the fix, the reviewer's fixture passes (`code=0`), and SPEC 18.6.2 gained one sentence after the Console block. `Campaign.handover` keeps the same defect, scoped out by this finding.

Location: `statelens/scripts/statelens.py`, `Synthesis.run_lines`.

Generated commands interpolate checkout and crash paths without shell quoting. Executing the run line in an ordinary directory containing spaces returns `cd: too many arguments` and exit 2. The older campaign handover has a similar limitation; this finding concerns the new TSS command generator.

Suggested fix: construct arguments with `shlex.join` or quote paths with `shlex.quote`.

Evidence: [workflow fixture](/private/tmp/tss_r2_workflows_checks.py), `WorkflowReview.test_handover_quotes_a_checkout_with_spaces`.

**12. Criticality: low - Extraction accepts an untracked test that its required citation cannot identify. SHOULD FIX.**

Status: FIXED (2026-10-08). `check_test_sources` in `statelens/scripts/statelens.py` now refuses a `test` source whose file is not in HEAD, through the rule-10 helper `git_file(repo, "HEAD", relative)`, with exit 1 (`... is not in HEAD, the commit a card cites its test at; commit the file first, or give the test as a `text` source`) before the agent runs, so preflight and lint agree by construction; `unpinnable` is unchanged, so a tracked test modified in the worktree still passes with its warning. Regression test `ExtractStates.test_a_test_that_head_does_not_have_is_refused_before_the_agent` (an untracked and a merely staged file are refused with `self.phases == []`; a tracked-and-modified control passes and is listed by `unpinnable`) fails without the fix (`Abort not raised`), the reviewer's fixture now errors at its direct `check_test_sources` call, which is the intended preflight rejection, and SPEC 18.4 and PRD R-TS-P1-2 state the HEAD condition. `comment` sources have the same gap (`check_comment_sources` checks `exists()` only), outside this finding and left open.

Location: `statelens/scripts/statelens.py`, `check_test_sources`, `unpinnable`, and `extract_states`; `statelens/prompts/state-analyst.md`, source-citation requirements.

An existing untracked test inside an allowed source root passes preflight. `unpinnable` ignores `??`, while the analyst must cite the file at HEAD, where it does not exist. The agent runs and writes a compliant card before post-lint rejects its citation with exit 3. The documentation does not state that only files present at HEAD may be selected.

The final lint correctly blocks the invalid card. The defect wastes an agent attempt and delays an actionable provenance error.

Suggested fix: reject sources absent from HEAD before invoking the agent, with commit/use-text guidance, or define explicit local-test provenance.

Evidence: [extraction fixture](/private/tmp/tss_r2_extraction_check.py).

**13. Criticality: medium - Rollback through a newly introduced symlink can overwrite an unchanged sibling. SHOULD FIX.**

Status: FIXED (2026-10-08). `Synthesis.write` in `statelens/scripts/statelens.py` returns with a warning (`<path> lies behind a symbolic link; it was not restored`) when the path's parent resolves elsewhere than the scope's directory, a directory guard 1 already names with exit 2, and unlinks a symbolic link at the path before writing or deleting, pruning the parent when a link or a file was removed, so a restore never writes through a link; `snapshot` and `restore` are unchanged, since snapshots hold regular files only and no temporary-file-and-rename is needed. Regression tests in the new class `RestoreLinks` (`test_a_file_replaced_by_a_link_is_restored_as_a_file`, the finding's shape, and `test_nothing_is_written_below_a_directory_a_link_replaced` fail without the fix; `test_a_link_an_edit_added_is_removed_not_followed` is a control), the reviewer's fixture passes 2/2, and SPEC 18.6.2 step 1 and 18.11 describe the rule. Documented, not fixed: a dangling link, or a link to a directory, that an edit leaves in the scope is not listed by `scope_files` and survives a restore; nothing compiles or reads it.

Location: `statelens/scripts/statelens.py`, `Synthesis.snapshot`, `write`, and `restore`.

Snapshots retain file contents without file type. If an allowed regular source becomes a symlink to an unchanged sibling, restoring the original contents writes through that link. Rollback overwrites the sibling and leaves the source as a symlink, rather than restoring the original regular file.

The fixture replaces an allowed tracked scalar source with a link to an unchanged tracked template. Before restoration, `outside_scope` reports no outside edit. Restoration itself changes the template outside scope. The expected-safe assertion that the sibling remains unchanged fails.

The trigger requires an uncommon link-producing edit. README gives synthesis full machine control on a dedicated disposable clone; the evidence therefore supports a restoration defect, without claiming a security isolation failure or high impact.

Suggested fix: preserve and restore file type, writing regular files through a temporary file and rename; or reject new symlinks and remove them before restoring regular sources. Check affected parent directories as well.

Evidence: [symlink rollback fixture](/private/tmp/tss-pass2-symlink-rollback.py) and [root confirmation](/private/tmp/tss-r2-root-symlink-confirmation.log). Every path is a harmless temporary scalar file.

**Validation and limits**

`just check-scripts` passed all 431 tests with the reviewed script/test files unchanged; log: `/private/tmp/tss-final-fix-check-scripts.log`. `just check-prompts` reported zero problems. Focused existing checks also passed: 22 isolated runtime/helper tests, 35 reach-verifier tests, 57 workflow tests, 92 lifecycle/command tests, and 49 verifier/card tests in the second semantics pass. These groups overlap and are not additive. The new expected-safe assertions fail as documented above. Original finding 4/V1's 24 focused controls and current V2/V3 regressions pass.

The high dependency finding has actual Rust compilation, actual unchanged-helper output and real verdict parsing; Cargo/agent dispatch is substituted. The control findings use compiled helper fixtures with scalar dependencies. Process-interruption checks use real harmless subprocesses. Other orchestration checks use temporary repositories and mocked builds/reach outcomes. Static evidence supports the prompt finding. Full generated protocol campaigns were not executed, so this review does not establish end-to-end Simplex or Marshal behavior.

All 23 prompt files, their dynamic assembly and SPEC copies, the template and all four target cards were reviewed. The fresh final passes examined runtime/helper/parser/prompt contracts and all synthesis transaction/guard/rollback/revalidation/final-handover paths. Their source hashes matched the initial snapshot.

Two runtime candidates were excluded after independent evaluation: cached intrinsic observations across a second constructor violate the documented fresh/latest-read rule; exact witnesses across independent runtimes lack an established supported base trigger. Neither is counted as a confirmed critical/high finding.

Independent control evaluation and positive controls: [results](/private/tmp/tss-r2-controls-eval-evidence/summary.json). Prompt coverage and hashes: [inventory](/private/tmp/tss-r2-prompt-review-my9q9oy5/evidence.json).

| Reviewed file | SHA-256 |
| --- | --- |
| `statelens/scripts/statelens.py` | `7fcc830485f4abd98141f612e775f19add902a589921957e12f548f2dc2549b8` |
| `statelens/scripts/test_statelens.py` | `7878d7e1e05bbcab5494ddac3247c998038986e6322084e0ca3c37330ae2f435` |
| `statelens/runtime/target_states.rs` | `551ed5251f6429cbc1c3d4cba4b675d2c70d7047983ccf7260a3c2f22c23f84f` |
| `statelens/runtime/statelens.rs` | `72f549efe22a41b2abf2238f83bb6a9e135ae997876da50e5f80f70fe006d26a` |
| `statelens/prompts/synthesize.md` | `c6ad12e9f3217648991ba438440935db4a18ea4b6142acdde29f2804e0bb964f` |
| `statelens/prompts/subsystems/simplex-synthesize.md` | `0332e9f8420b611ff3007451b08165d6a9eaa0cd760069cdfaaab1f052d23384` |
| `statelens/docs/SPEC.md` | `9deb6eeb9946bd087156a886da918d32008f2453cf5bb1fd96beee0bbdc23916` |
| `statelens/justfile` | `eed8316e232b861e7d4732a91c1d39d0770f23cb8f530cded1b057bcd6105713` |
| `statelens/README.md` | `7d7972014e78e9735910873eff4868ee305caedd2b44f3b5f002dfb950a19922` |

**Selector-rename follow-up, 2026-10-08**

Two fresh-context reviewers checked the renamed flags, their documentation and tests. The actual `just fuzz` recipe routes `--state-targets` and `--fuzz-targets` as the intended `--match` arguments, preserves quoted patterns and libFuzzer arguments, forwards `--invariants` only to the campaign, and rejects old `--targets`, selectors on the wrong flag and state-card selection without `--state-reaching`. The user's command is valid. No rename-introduced runtime defect or critical/high issue was established.

Root validation passed 33 focused tests: `FuzzRecipe`, `JustfileProfiles`, `TargetSelection`, `ScaffoldSelection`, `InvariantSelection` and `PlanProfile`. Prompt checks reported 0 problems, invariant checks reported 68 files and 0 problems, and `git diff --check` passed. The independent CLI reviewer additionally passed 34 actual-`just` stub scenarios with JSON argument capture; [results](/private/tmp/tss-rename-cli-review-efqy_7x6/review-validation.json). These groups overlap with existing tests. The claimed full 460-test suite was not rerun in this follow-up; 460 test methods were independently discovered. SPEC section 5.3 is byte-equal to the justfile, both plan copies are identical, and remaining active old-flag references are deliberate rejection tests.

The review separately called real `select_scaffolds` against the current checkout. TS-0004 with `simplex_cert_mock_twins_*` selects eight candidate bases: `simplex_cert_mock_twins_campaign` and `simplex_cert_mock_twins_mutator`, each with its plain, `_audit`, `_hb` and `_state_cov` forms. Synthesis chooses a base from that set; no generated scaffold or protocol campaign was run. This separates verified argument routing from the inaccurate exact-output prediction below. Implementation and repository tests were not edited.

**14. Criticality: low - The new example predicts a scaffold name whose base does not exist. CONSIDER.**

Status: FIXED (2026-10-08). Superseded by the per-base change: a card now gets one scaffold per base `--fuzz-targets` matches, named `<base>_tsNNNN_statelens`, so the example lists the eight twins scaffolds, `simplex_cert_mock_twins_campaign_ts0004_statelens` to `simplex_cert_mock_twins_mutator_state_cov_ts0004_statelens`, and the name is no longer a prediction of the agent's choice; SPEC section 18.9 and `FuzzRecipe.test_an_invariant_list_goes_to_the_campaign` list all eight.

Location: `statelens/docs/SPEC.md`, section 18.9; `statelens/scripts/test_statelens.py`, `FuzzRecipe.test_an_invariant_list_goes_to_the_campaign`.

The SPEC says the new command runs `simplex_cert_mock_twins_ts0004_statelens`, and its regression test supplies that name as the listing stub's result. Under the existing naming contract, this requires a base `simplex_cert_mock_twins`. That base does not exist and is not among the real selector's eight candidates. A real generated name retains the full selected base, for example `simplex_cert_mock_twins_campaign_ts0004_statelens`.

Impact: the recipe test establishes forwarding and execution of the stub's supplied name, but cannot validate this exact generated-name claim. The input command remains valid; copying the promised resulting target into a later `just run` would name an unavailable target. This is a documentation/test-fixture inaccuracy, not a flag-routing failure.

Suggested fix:

a) Keep the wildcard selection and describe the result as `<chosen-base>_ts0004_statelens`; use a real selected base's name in the forwarding fixture.
b) If a fixed resulting name is required, narrow `--fuzz-targets` to an existing concrete base, such as `simplex_cert_mock_twins_campaign`, and use its full scaffold name in the example and test.

Evidence: [read-only expected-correct check](/private/tmp/tss-flag-rename-review-924lvdcx/check_example_name.py) and [output](/private/tmp/tss-flag-rename-review-924lvdcx/example-name.log). The documented-name assertion fails against real selection; the actual-base positive control passes. Two fresh reviewers and the root independently confirmed the mismatch. No synthesis or fuzzing was executed.

The [follow-up snapshot manifest](/private/tmp/tss-flag-rename-review-924lvdcx/manifest.json) pins the checked uncommitted tree against unchanged HEAD `8a0d2cef732b2607e8c742fa71ee438a97e42467`. Source references use symbols and sections, without unpinned source line numbers.

| Follow-up checked file | SHA-256 |
| --- | --- |
| `statelens/justfile` | `b11e828c062bbb5c4930921d6721b636ea4eb1b278cd1f02d7b8c4571939f3e9` |
| `statelens/scripts/statelens.py` | `94a5c272b5a05eec2f31fcbf19c337a7f9dd96fb7275d4f554bdfedaace78ad4` |
| `statelens/scripts/test_statelens.py` | `d3bc8393a8b3fcc021f8cd374055d36070f85758913d7d66b37c5a94d0d85a65` |
| `statelens/docs/SPEC.md` | `b6297925834753a3f52d42cb1828ab1e674920d9058e28511646b25767f2d21b` |
| `statelens/statelens-tss-plan.md` | `b96df165c370952839f7b6a9ef3ac4737a11d686ee2b44ab5b4df61e0a26af1e` |
