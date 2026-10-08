**Target-State Synthesis: fix-verification checkpoint**

Verification date: 2026-10-08. The original fix verification, requested [second full review](statelens-code-review-target-state-round-2.md), and validation of its subsequent fixes are recorded for their respective snapshots below.

All 20 original findings are now resolved for their stated operational causes. Fresh validation closes original finding 4's dependency-classification residual: own-module edits are shared, and compiled scalar fixtures with explicit and implicit dependencies confirm revalidation and rollback. Round-2 finding 1's separate report-publication rollback defect is also fixed. The remaining issue is round-2 finding 5, PARTIALLY FIXED at medium severity: `control_status` accepts an incarnation contradicted by restart metadata as evidence of another final state. No outstanding critical/high issue was established in this fix validation. Current script SHA-256 is `6d1f251f73fb87b70ebe9e518e8dd17efab2c4dd99ead1396f7d630df1596d7b`; tests are `c8844d85b77108ca5da923f28c9b04e02e005519fcbac7404ba0ba9c1aea0004`. The clean current checks passed 451 script tests, prompt validation with 0 problems, and invariant validation over 68 files with 0 problems. See the round-2 report for current per-finding validation and evidence.

Historical checkpoint: ordinary finding-4 regressions, V1, V2 and V3 passed on script `7fcc830485f4abd98141f612e775f19add902a589921957e12f548f2dc2549b8`; tests were `7878d7e1e05bbcab5494ddac3247c998038986e6322084e0ca3c37330ae2f435`, with 431 script tests passing unchanged. The subsequent dependency and report-publication cases were then tracked as round-2 findings 2 and 1, respectively. The older evidence below is retained as history.

Reference correction: finding 19's `run_standard_once` example is in `consensus/fuzz/simplex/src/lib.rs`, not Marshal. The original report names the correct source, and the shared-prompt conflict is now fixed.

Historical verification: both V1 and V2 reproduced after the medium-finding edits on the earlier snapshot below. Logs: `/private/tmp/tss-current-redo-verification.log` and `/private/tmp/tss-current-sweep-verification.log`. Four fresh-context evaluators checked those edits; a fifth independently evaluated the cleanup residual and the scope of finding 13. The root reviewer also reran the original replay-preservation controls and all three residual cases.

Earlier follow-up: the script subsequently changed to SHA-256 `f382893840d7403ca43dc5748fb5193428b041b3fb837da8b6a1f482c2efbbfd`, with tests `4ec4aa9422f7e8bbeb9fe730ac7d7a3a78daf827f5d07cd90bf853931024ab2a`. V1 and V2 still failed on that version, while V3 returned failure accurately on both cleanup attempts. Logs are `/private/tmp/tss-latest-residual-v1-20261008.log`, `tss-latest-residual-v2-20261008.log`, and `tss-latest-residual-v3-20261008.log` in the same directory; the root's V3 recheck also passed (`/private/tmp/tss-current-clean-fixed.log`). A source snapshot is retained in `/private/tmp/tss-monitored-snapshot-iocbve1g/`.

The next fix evaluation passed both original finding-4 fixtures, 15 independent durable-undo lifecycle cases and six repository regressions. V2 passed 23 focused checks covering the original replay-preservation controls, interrupted moves, partial collections, failure classification and retained source snapshots. Evidence is in `/private/tmp/tss-durable-undo-eval-20261008-9egxqdgy/` and `/private/tmp/tss-swept-recovery-20261008-zri3nhi1/`. The existing full script suite passed 421 tests, but the source changed during that run; this is not a clean full-suite certification of the final revision.

Final verification of the subsequent revision is retained in `/private/tmp/tss-final-undo-7fcc-eval-j00otoz7/` (24 passing checks) and `/private/tmp/tss-rollback-scope-eval-20261008-tnbu6bc_/` (seven passing original-cause controls and the distinct report-publication residual). Root rechecks of V2 and V3 passed; their logs are `/private/tmp/tss-current-v2-final-verification.log` and `/private/tmp/tss-current-v3-final-verification.log`. The clean 431-test run is `/private/tmp/tss-final-fix-check-scripts.log`.

The author's later PARTLY FIXED labels for 8 and 20 described historical overlap with earlier fixes. Separate fresh evaluators confirmed both original operational causes are fully resolved: 13 focused reference-restoration cases and five pending-recovery cases passed. Their statuses now distinguish current resolution from historical triage. Evidence: `/private/tmp/tss-finding8-disposition.py` and `/private/tmp/tss-finding20-disposition-20261008.py`.

The latest Simplex and Marshal prompt revisions and card explanations were also checked: 23 rendering, copy-consistency, lint and scalar-parser assertions passed. Static source inspection supports the TS-0001 timeout explanation; no protocol probe was run and reaching the E6-first variant was not established. Evidence and all 56 stable input hashes are in `/private/tmp/tss-latest-status-20261008-jldkv4qy/`.

| Original finding | Verified disposition | Evidence |
| --- | --- | --- |
| 1: trace truncation | FIXED | The runtime retains the first dropped position; helper and parser reject witnesses read after that cut and suppress held handoff. Eleven focused checks passed, including a fresh scalar runtime-to-parser check returning UNVERIFIED 1/2. |
| 2: nextest gate | FIXED | Forced rendering, validated summaries and exits, persisted test inventory, and fail-closed gate handling cover the reported cause. Twenty-five focused tests, six real arithmetic-only nextest runs, and an independent resume check passed. |
| 3: interrupted replay loses source | FIXED for the original cause | Source is saved before scripted replay. The original canonical-failure/control-interruption regression, final-replay interruption, and harmless real SIGINT checks pass. The separate sweep interruption V2 now passes too. |
| 4: shared changes invalidate earlier scaffolds | FIXED; V1 FIXED | Ordinary shared-edit revalidation/rollback, signature failure and durable undo pass. Current round-2 fixes also pass explicit/implicit own-module dependency checks and interrupted report-publication rollback checks. Temporarily unbuildable dependents remain conservatively NOT BUILT until redo, rather than falsely REACHED. |
| 5: final-stage unverifiability | FIXED | Explicit final unverifiable outcomes and reasons survive handoff in one-stage and two-stage fixtures. |
| 6: incomplete control acceptance | FIXED | Missing completion/reach lines, invalid totals, and parser problems are rejected. The original fixture returns UNVERIFIED. |
| 7: positionless incarnation validation | FIXED | Incarnation existence is checked independently of position; the original unknown-incarnation fixture is rejected. |
| 8: persisted guard references | FIXED | `seal` restores persisted records after agent exit and interruption; original cross-invocation fixtures and an independent restoration/resume check pass. |
| 9: stray source snapshot after guard restoration | FIXED | The original manifest-preservation regression passes. V2 concerns a distinct interruption during artifact relocation. |
| 10: archived replay paths | FIXED | Archived reports, replay commands, and interruption notes point to the moved crash input. |
| 11: old package crash artifacts after redo | FIXED | Redo moves the selected artifact directory into the archive while retaining the corpus. |
| 12: custom Cargo target directory | FIXED | Absolute/relative custom directories are honored, and lookup rejects a stale default binary when a custom directory is selected. |
| 13: ignored generated Rust survives cleanup | FIXED for the original cause | The ignored-source regression passes. V3's distinct false-success cause has since been fixed too. |
| 14: disabled-reporting trace allocation | FIXED for the reported paths | Both measured maximum allocations fell from 67,108,864 bytes to 96 bytes. Reporting-enabled full-trace allocation remains. |
| 15: setup before observation starts | FIXED | Prompt, helper lifecycle, SPEC, and PRD agree on opening stages and checking the budget before witnessed setup. |
| 16: incompatible generic continuation rules | FIXED | Shared guidance delegates to base-specific progress/deadline rules and requires Shape B when needed; Marshal guidance matches the referenced implementations. |
| 17: entropy-dependent Twins case | FIXED | Prompt and SPEC explain the sampling dependency and direct fixed-history requirements to Shape B. |
| 18: omitted card identities | FIXED | Both entity references are present; actual parser/witness checks reject missing and mismatched identities. |
| 19: inherited oracle versus panic prohibition | FIXED | The no-panic rule covers newly written prefix/witness code, with an explicit inherited-driver/oracle exception. |
| 20: abandoned-target handover | FIXED | Persisted per-card snapshots recover the pre-attempt tree. Failed resumed build and subsequent skipped invocation both return 3 without a handover. |

**V1. Criticality: high - Interrupted redo leaves an obsolete REACHED verdict after successful resume. MUST FIX.**

Status: FIXED (2026-10-08). `Synthesis.undo` (`statelens/scripts/statelens.py`) records the owed revalidation in `SL/campaign/reach/revalidation.json` (`Synthesis.owe`) once `git apply -R --check` accepts the diff and before it reverse-applies it, and `Synthesis.revalidate_owed` completes it before any card in every synthesis (`run_cards`) and at the end of `last_check`, deleting the record only on success. Regression `Synthesize.test_an_interrupted_redo_revalidation_is_completed_by_the_next_synthesis`, with no-card, last-check, unreadable-record, failed-undo and interrupted-undo variants, passes, and this fixture, copied and run against the current tree, now resumes with PARTIAL 1/4 (still REACHED 4/4 on `f3828938...`); `just check-scripts` runs 431 tests, OK, on `statelens.py` `7fcc8304...`.

This is the remaining portion of original finding 4, not an additional high finding.

Location: `statelens/scripts/statelens.py`, `Synthesis.redo_cards`, `revalidate_undone`, `check_scaffold`, `load_standing`, and `last_build`.

`redo_cards` removes shared edits and archives the selected card before revalidation finishes. The obligation to revalidate exists only in memory. Interrupting an earlier scaffold's control replay leaves its old report authoritative. On resume, an own-file-only replacement causes no further shared-code revalidation, and the final build check establishes compilation only.

The focused regression starts with an earlier scaffold that reaches only while a later card's shared accessor exists. Redo removes that accessor, then interruption during the earlier scaffold's control replay returns 130. Its completed canonical replay records `reach 1/4`. A subsequent synthesis returns 0 and rebuilds both scaffolds, but the earlier report still says `REACHED 4/4`.

The interruption window includes builds and multiple replays. Ordinary cancellation therefore leaves a false certification that survives a successful invocation. This supports retaining high severity within the original review's correctness scale.

Suggested fix: a) Persist pending revalidation before undoing shared edits and complete it before resumed selection or success. b) Alternatively, restore the pre-redo tree and metadata when revalidation is interrupted.

Evidence: [focused lifecycle verification](/private/tmp/tss_finding4_verification_20261008.py), `Finding4Verification.test_interrupt_after_redo_does_not_leave_stale_reach_after_resume`. The root reviewer and two fresh-context evaluators independently reproduced the failing expected-safe assertion. Reach outcomes use the repository's existing mocked scalar-accessor fixture; this establishes the orchestration error, not a real Simplex or Marshal behavioral regression. The ordinary signature rollback control uses actual `rustc`.

**V2. Criticality: medium - Interrupted artifact relocation can preserve a stray failure while losing its source. SHOULD FIX.**

Status: FIXED (2026-10-08). In `Synthesis.preserve` (`statelens/scripts/statelens.py`), the re-sweep branch (`live["before"] is not None`) now takes the attempt's stray failures from the files in `attempt-<a>/swept/` rather than from what the re-sweep returns, so a sweep stopped after a move, or after it returned but before `attempt` recorded its failures, still keeps the version; the scan stays inside that branch so a later attempt's strays still reach a kept attempt's note. Regressions `Synthesize.test_an_interrupt_after_the_sweep_moved_a_stray_failure_keeps_its_version` and `test_an_interrupt_after_the_sweep_returned_keeps_the_version` fail on `f3828938...` and pass now, the control `test_an_interrupted_finish_names_a_later_attempts_stray_failure` passes, and this fixture, copied and run against the current tree, passes 4/4.

This is a separate narrow residual. It does not reopen finding 3's original canonical-replay failure.

Location: `statelens/scripts/statelens.py`, `Synthesis.sweep`, `preserve`, and `synthesize`.

`sweep` moves an artifact before returning its failure list. An interruption after the move leaves `live["failures"]` empty. Exception cleanup repeats the sweep, but the moved artifact is no longer in the live source tree. Cleanup therefore skips the source snapshot and restores away the generated scaffold.

The regression retains `swept/crash-safe-fixture` and `interrupted.txt`, but no `version.diff` or source copy. The note incorrectly says that no version was replayed or left a stray failure. This requires both a stray artifact from an agent's run and interruption during relocation bookkeeping, so medium severity is appropriate.

Suggested fix: a) Preserve source before relocating identified failures, or journal moved failures so exception cleanup can recover their destination paths before deciding whether a snapshot is needed.

Evidence: [focused interruption verification](/private/tmp/tss_high3_eval_20261008.py), `High3.test_interrupt_after_sweep_move_preserves_source`. The root reviewer and two fresh-context evaluators independently reproduced the failing expected-safe assertion in temporary repositories.

**V3. Criticality: medium - Repeated clean reports success while an empty generated directory blocks reuse. SHOULD FIX.**

Status: ALREADY FIXED (2026-10-08). The medium refix (script `f3828938...`) fixed it before this round: `cmd_clean` (`statelens/scripts/statelens.py`) collects each surviving `scaffold_dirs()` directory as `stale` and takes its no-work success return only when nothing is stale, so a repeated clean reaches the post-check, reports `?? <package>/src/target_states/` and exits 1, as `Campaign.check_preconditions` refuses the same checkout; clean still leaves the empty subtree to the operator, by design, which this finding accepts. `cmd_clean` is unchanged since, `Cleaning.test_a_target_states_directory_left_is_reported` covers the repeated clean, and this fixture, copied and run against the current tree, passes with `first=1; repeated=1`.

This is a separate residual. Finding 13's ignored-Rust cause is fixed; this case has no surviving files and follows the no-work return path.

Location: `statelens/scripts/statelens.py`, `cmd_clean`, `clean_plan`, and `Campaign.check_preconditions`.

With `src/target_states/empty/` and `src/target_states/mod.rs`, the first clean deletes the source and returns 1 because the generated directory remains. The next cleanup plan contains no files to delete or restore. `cmd_clean` returns 0 immediately, bypassing its remaining-directory check. The surviving `target_states/` still causes the next campaign's precondition to fail with exit 2.

The root reviewer and two fresh-context evaluators reproduced the cleanup behavior. The independent evaluator also checked actual campaign preconditions: they accept the initial checkout and reject it after the repeated cleanup. The original ignored-Rust regression passes.

Suggested fix: a) Prune empty generated directories safely, or check for surviving generated directories before the no-work success return. Cover both initial cleanup and a repeated invocation.

Evidence: [focused cleanup verification](/private/tmp/tss_pending_workflow_verification_20261008.py), `CleanupRemainder.test_repeated_clean_does_not_claim_success_with_an_empty_generated_directory`; root log `/private/tmp/tss-current-clean-verification.log`. The current fixture expects first-clean exit 1; an eventual fix that removes the empty subtree and returns 0 immediately is also valid and should be accepted by the regression.

**Scope and snapshot**

These are disposition checks with fresh-context auditors and additional independent evaluators for the residuals. No implementation files were edited. Tests use scalar states, temporary repositories, mocked replay outcomes, and harmless compiler/subprocess checks; no protocol fuzzing or complete generated campaign was run.

For the earlier medium-fix batch, the runtime evaluator passed 20 focused checks; the verifier/gate evaluator passed 28; the workflow evaluator passed nine repository checks, the original stray-snapshot fixture, and the pending-recovery fixture; the prompt evaluator passed 21 consistency/rendering/parser assertions and the card regression. The root's three replay-preservation controls passed. The expected-safe assertions for V1, V2, and V3 initially failed as described; their subsequent fixes and passing rechecks are recorded above. These overlapping focused counts are separate from the final 431-test full-suite result.

The checked working tree is uncommitted against HEAD `8a0d2cef732b2607e8c742fa71ee438a97e42467`. Source locations use paths and symbols rather than unstable line numbers. These hashes identify the batch that verified the 19 original fixes; later follow-up hashes and results are recorded above. The report hash records its state before those verified-disposition annotations.

| File | SHA-256 |
| --- | --- |
| `statelens/scripts/statelens.py` | `cd89ef50c74ae3b3c0542f30dd4fd4c8c85d3f83bdb42d2e0d4a774659b78f54` |
| `statelens/scripts/test_statelens.py` | `5945df243e06ccd3e6c9041fd51f58255fd83598b015dc487db27d070604faad` |
| `statelens/runtime/target_states.rs` | `551ed5251f6429cbc1c3d4cba4b675d2c70d7047983ccf7260a3c2f22c23f84f` |
| `statelens/runtime/statelens.rs` | `72f549efe22a41b2abf2238f83bb6a9e135ae997876da50e5f80f70fe006d26a` |
| `statelens/docs/SPEC.md` | `eade7c9f839497c9fa02b9272538251c64cc8934eef0e822f38b8c28a9d36ea3` |
| `statelens/docs/PRD.md` | `e57accf010f37eac2f396cdf903759cafc6377420d3c89f872a880d0de4c9281` |
| `statelens/prompts/synthesize.md` | `c6ad12e9f3217648991ba438440935db4a18ea4b6142acdde29f2804e0bb964f` |
| `statelens/prompts/subsystems/marshal-synthesize.md` | `4bfd310c5bac547a66d8abef68314995883ae1b98418fe6a6daf91238112de82` |
| `statelens/target-states/marshal/TS-0001.md` | `5d7af4b641ddd0d8492de9bf46381f220c26a768d0659f1937ee775f36f0c040` |
| `statelens/target-states/marshal/TS-0002.md` | `53832fad0a7031d7da45e3a701ff108cd0497f21a5600494d3e7d23018b97655` |
| Original report before latest annotations | `44e43e8a43fbfed0bc6faa668490b974ccc5fa327cce32eeefa718d393c80990` |

Supporting results for the fixed findings are retained in `/private/tmp/tss-high1-disposition-x0io2csz/` and `/private/tmp/tss-status-high2-nextest-8covcoum/`. Temporary evidence paths refer to this review environment.

Latest evidence: `/private/tmp/tss-current-runtime-verification-2t0sc6lb/`, `/private/tmp/tss-pending-fix-verification.py`, `/private/tmp/tss_pending_workflow_verification_20261008.py`, `/private/tmp/tss-pending-prompts-20261008/`, and `/private/tmp/tss-current-replay-preservation.log`.
