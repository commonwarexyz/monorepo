**Target-State Synthesis implementation review**

Review date: 2026-10-07. Status: complete for the reviewed snapshot.

Fix verification, 2026-10-08: all 20 original operational causes are resolved, and V1-V3 pass. Fresh validation of round-2 finding 2 confirms that own-module changes now revalidate dependent scaffolds, closing original finding 4's remaining high case. The [second review](statelens-code-review-target-state-round-2.md) records the later fix validation: its finding 5 retains a medium control-identity residual. No outstanding critical/high issue was established in that validation. The [fix-verification checkpoint](statelens-code-review-target-state-verification.md) records the checked snapshots.

The initial review reported **4 high and 16 medium**. No critical finding was established. The historical high findings concerned false reach certification, a test gate that could accept failures, loss of a failure's generated source, and accepted scaffolds becoming invalid after subsequent synthesis. Their current dispositions are recorded below.

This report covers the uncommitted TSS implementation against HEAD `8a0d2cef732b2607e8c742fa71ee438a97e42467`, including new untracked TSS files. Locations use paths and symbols, without unstable source line numbers. No implementation files have been changed during this review.

**1. Criticality: high - Truncated traces can certify an obsolete final state. MUST FIX.**

Status: FIXED (2026-10-08). The runtime records where it first dropped an observation (`statelens/runtime/statelens.rs`, `truncated() -> Option<u64>`); the helper (`statelens/runtime/target_states.rs`, `settle` and `Stages::handoff`) prints `truncated seq=<s>`, reports every stage read at or after it as `unverifiable (trace truncated)` with no feature, and cannot hold the handoff; the script rechecks this, so the verdict cannot be REACHED, and guard 3 (`Synthesis.integrity`, `HELPER_ONLY`) vetoes `watch`/`unwatch` outside the helper so a scaffold cannot forget the truncation. Regressions: the helper self-tests in `target_states.rs` and the captured runtime-to-parser and synthetic cases in `scripts/test_statelens.py`; the reviewer's fixture now gives UNVERIFIED 1/2.

Location: `statelens/runtime/target_states.rs`, `settle` and `Stages::handoff`; `statelens/runtime/statelens.rs`, observation storage and truncation.

`settle` converts only a missed outcome to unverifiable after trace truncation. A held outcome still contributes features and can certify handoff. Once the trace cap is reached, the latest retained observation can describe a state that has since changed. This violates the specified treatment of stages evaluated after truncation.

Evidence: a scalar Rust fixture using the actual helper and the unchanged runtime read-side implementation filled `TRACE_CAP` with state `1`, then recorded state `0`, which was dropped. Reading the latest retained observation inside handoff produced `REACHED 2/2` through the actual Python validator. This is distinct from the documented witness-provenance limitation: the helper already knows observations were lost.

Suggested fix: a) Downgrade held results evaluated after truncation, including the final handoff result, to unverifiable; suppress their features and held-handoff evidence. Add a runtime-to-parser regression that changes state after the cap.

**2. Criticality: high - Normal nextest output settings can disable the test gate. MUST FIX.**

Status: FIXED (2026-10-08). `nextest_command` forces the rendering (`NEXTEST_RENDERING`: `--color never --message-format human --status-level pass --final-status-level fail --success-output never --failure-output immediate`), and `nextest_run` strips ANSI codes and validates every run against nextest's summary line, failing closed on unusable output, build failures and unexplained nonzero exits; the validated inventory is persisted with the baseline (`Synthesis.take_tests`, `reach/baseline/tests.json`), a READY campaign records no failing test, and `Synthesis.gate` never ignores the exit code. Regressions: `TestGate` and `Synthesize` tests, including `test_the_reviewed_gate_that_exited_100_fails`; checked with real cargo-nextest 0.9.127 under `NEXTEST_STATUS_LEVEL=fail`, `CARGO_TERM_COLOR=always` and nextest config files.

Location: `statelens/scripts/statelens.py`, `nextest_command`, `PASSED_TEST`, `passed_tests`, `Synthesis.load_campaign`, and `Synthesis.gate`.

The passing-test parser accepts only plain `PASS [` lines, while the test command leaves status verbosity and color configurable. `NEXTEST_STATUS_LEVEL=fail` suppresses passing-test lines; `CARGO_TERM_COLOR=always` adds ANSI formatting. A successful campaign can therefore establish an empty passing-test baseline. With that baseline present, `gate` compares sets and ignores the rerun's failure exit code, allowing the failed gate to pass.

Evidence: real nextest runs on a harmless one-test Cargo project succeeded under both settings and parsed as zero passing tests. Both orchestration regressions then retained a marked SUT edit, returned synthesis exit `0`, and reported `REACHED 4/4` and a passed gate although the gate exited `100`.

Suggested fix: a) Use stable machine-readable results or force and validate stable rendering. Persist a validated test inventory and fail closed on unusable output, build failures, and infrastructure failures while preserving the policy for explicitly recorded preexisting test failures.

**3. Criticality: high - An interrupt can discard the source of an already preserved failure. MUST FIX.**

Status: FIXED (2026-10-08). Synthesis saves each version's full source (`version.diff` and `version/`) before any replay, and `Synthesis.preserve` keeps the version, every replay log and crash file, and writes `attempt-<a>/interrupted.txt` (including a crash file an interrupted replay already left) before the tree is restored. Regressions: `test_an_interrupt_keeps_a_failed_replay_and_its_whole_version`, `test_an_interrupt_after_a_replay_left_a_crash_file_names_it` and related tests; checked with interrupts at every replay boundary and a real SIGINT.

Location: `statelens/scripts/statelens.py`, `Synthesis.attempt`, `keep_version`, and `synthesize`.

The source `version.diff` is saved only after both canonical and control replays finish. If the canonical replay fails and the operator interrupts the control replay, exception cleanup restores the starting tree before preserving the generated source.

Evidence: an isolated regression returned `130` and retained the canonical crash file and log, but removed the generated scaffold and left no `version.diff`. A compiled executable may remain temporarily; the source needed to inspect and rebuild that failure is lost.

Suggested fix: a) Save the complete accepted source version before starting any replay. Preserve available replay metadata during interruption cleanup.

**4. Criticality: high - Later cards can invalidate previously accepted scaffolds without revalidation. MUST FIX.**

Status: FIXED (round-2 fix validation, 2026-10-08). Ordinary shared-edit revalidation and durable undo pass, including V1. `Synthesis.shared_paths` now treats the current card's own module as shared; kept changes and undo revalidate other standing scaffolds. A fresh evaluator checked explicit helper calls and implicit inherent-method/trait dependencies using actual Rust compilation and the unchanged reach helper. Breaking changes are rolled back; retained reports agree with fresh execution. A temporarily unbuildable dependent remains conservatively NOT BUILT until `--redo`, as documented, rather than retaining false REACHED. See round-2 findings 1 and 2 in [the second review](statelens-code-review-target-state-round-2.md); the distinct report-publication rollback defect is also fixed. Checked script SHA-256: `6d1f251f73fb87b70ebe9e518e8dd17efab2c4dd99ead1396f7d630df1596d7b`; tests: `c8844d85b77108ca5da923f28c9b04e02e005519fcbac7404ba0ba9c1aea0004`. [Current lifecycle validation](/private/tmp/tss-r2-lifecycle-validation-hxRdseCS/validate.py).

Verified fix history: When a kept version changes shared files (`Synthesis.shared_paths`), `Synthesis.revalidate` rebuilds and replays every earlier kept scaffold, updates its report, and rolls the later card back as NOT BUILT (`breaks TS-NNNN`) when an earlier scaffold no longer builds or stands worse; `--redo` and the last check's undo revalidate shared edits (`Synthesis.revalidate_undone`), and the last check rebuilds every kept scaffold (`Synthesis.last_build`, exit 2 on failure). The interrupted-undo residual (V1 in [the fix-verification checkpoint](statelens-code-review-target-state-verification.md)) is fixed in `statelens/scripts/statelens.py`: `Synthesis.undo` records the revalidation it owes in `SL/campaign/reach/revalidation.json` (`Synthesis.owe`) once `git apply -R --check` accepts the diff and before it reverse-applies it, and `Synthesis.revalidate_owed`, called in `run_cards` before any card whatever is selected and at the end of `last_check`, completes it and deletes the record only on success; a diff that already applies forward, left by an undo an interrupt stopped before the card's reports moved, is not applied again, and an unreadable record exits 2. Regressions: `Synthesize.test_an_interrupted_redo_revalidation_is_completed_by_the_next_synthesis`, `test_a_synthesis_of_no_card_completes_an_interrupted_revalidation`, `test_an_interrupted_last_check_revalidation_is_completed_by_the_next_synthesis`, `test_an_unreadable_revalidation_record_stops_synthesis`, `test_an_undo_that_does_not_apply_records_no_revalidation`, `test_a_redo_completes_an_undo_an_interrupt_stopped_before_the_reports_moved` and `test_a_revalidation_record_a_replay_removed_is_no_error` pass (`just check-scripts`, 431 tests), and the reviewer's `test_interrupt_after_redo_does_not_leave_stale_reach_after_resume`, copied and run against the current tree, now resumes with PARTIAL 1/4 (REACHED 4/4 on script `f3828938...`); a fresh verifier's interrupts at each revalidation build and replay, a second interrupt during the resume and malformed records also pass. An interrupt inside `undo` itself, between its reverse-apply and its manifest edit, stays out of scope; the next run's baseline check stops it with exit 2 rather than leaving a stale verdict.

Reviewer verification: 24 focused durable-undo checks pass on script SHA-256 `7fcc830485f4abd98141f612e775f19add902a589921957e12f548f2dc2549b8`, including the original signature regression, interrupted redo, repeated interruption, skipped selection and recovery after a real child-process SIGKILL. A separate fresh evaluator passed seven ordinary shared-edit/rollback controls and identified the narrower report-publication rollback defect tracked as round-2 finding 1. Here the missing revalidation is fixed; the additional defect concerns restoring source after successful revalidation has already published an improved report.

Location: `statelens/scripts/statelens.py`, `Synthesis.attempt`, `scaffold_checks`, `finish`, `last_check`, and `run`.

Cards share an editable source tree, but synthesis builds and replays only the current card. A later change to an earlier module or shared code can invalidate an accepted target while its old reach report remains authoritative. The final instrumentation guard does not validate compilation or reaching behavior.

Evidence: a second-card fixture changed the first scaffold's `fuzz` signature. Both syntheses returned `0` and both reports remained `REACHED`; the earlier target was not rebuilt after the change. An actual `rustc` compilation of its caller succeeded before the edit and failed afterward with `E0061`.

Suggested fix: a) Rebuild and replay affected earlier targets after shared changes, updating their reports and rolling back a later card that breaks them. b) Alternatively, isolate each card's validated source tree and build.

**5. Criticality: medium - The helper cannot report that the final stage is unverifiable. SHOULD FIX.**

Status: FIXED (2026-10-08). `Stages::unverifiable` (`statelens/runtime/target_states.rs`) now settles stage n (`settle(.., true)`), so an `En` recorded unverifiable before `Stages::handoff` keeps its reason, the handoff calls no `read` and prints `handoff lost`, and the script gives UNVERIFIED with the "A witness that binds the relation" feedback; the handoff closure keeps its `Option<Witness>` type, since unverifiability is the scaffold's to declare, and `prompts/synthesize.md`, SPEC 18.7 and Appendix H say to call it before the handoff. Regressions: the helper self-test `imp::tests::test_unverifiable_last_stage_loses_the_handoff` passes with and without `STATELENS_REACH`, and the reviewer's `check_contract.py`, rebuilt against the live helper, passes 3/3.

Location: `statelens/runtime/target_states.rs`, `Stages::unverifiable`, `settle`, and `Stages::handoff`.

`unverifiable(n, reason)` is silently ignored by `settle`, and the handoff callback returns only `Option<Witness>`. `None` becomes a miss. A scaffold therefore cannot express that the final state's observables are insufficient, losing the reason and giving refinement the wrong diagnosis.

Evidence: the actual templates emitted `E2/2 missed not held at handoff` after an explicit final-stage unverifiable call. A one-stage variant similarly reported a miss.

Suggested fix: a) Let handoff return held, missed, or unverifiable outcomes while retaining fresh-read validation for held witnesses.

**6. Criticality: medium - An incomplete control run can certify reach. SHOULD FIX.**

Status: FIXED (2026-10-08). `control_status` (`statelens/scripts/statelens.py`) now calls a control vacuous ("the control run is incomplete: ...") when it has parser problems, such as lines under another card's ID or another `n`, or printed no `reach` or no `done` line, and `FEEDBACK_FIXES["control"]` asks for the control run to drive every later event, the handoff check and the base's oracles; SPEC 18.8, PRD R-TS-SYN-5 and the prompt, whose list of vacuous controls had left this out, now match. Regressions: the new no-`done`, no-`reach` and `TS-0009` cases of `ReachCheck.test_vacuous_controls` pass, and the reviewer's `test_control_return_before_done_cannot_certify_reach` now gives UNVERIFIED.

Location: `statelens/scripts/statelens.py`, `reach_verdict` and `control_status`.

Canonical reports are checked for reach output, completion, and structural problems. Control acceptance omits those checks. A control can withhold the chosen event, reach handoff, and return before the continuation's oracles and `done`, yet still validate the canonical result.

Evidence: removing only `done` from an otherwise valid control fixture still produced `REACHED 4/4`.

Suggested fix: a) Require a complete, structurally valid control report before accepting its causal result. Reject missing reach/completion and parser problems explicitly.

**7. Criticality: medium - Positionless witnesses bypass incarnation validation. SHOULD FIX.**

Status: FIXED (2026-10-08). In `reach_replay` (`statelens/scripts/statelens.py`), a held witness without a position is now rejected (`witness rejected: incarnation`) when a `bind=` value `inc<s>` names an `s` that no `restart` line's `seq=` gives; the positional checks are unchanged. Regressions: the new positionless `inc99` case of `ReachCheck.test_a_relation_across_a_restart` passes, and the reviewer's `test_unknown_incarnation_without_positions_is_rejected` now gives UNVERIFIED 0/1.

Location: `statelens/scripts/statelens.py`, `witness_rule` and `reach_replay`.

Incarnation-valued bindings are exempt from ordinary key evidence, and `reach_replay` skips incarnation checks entirely when the witness has no position. A permitted presence-only witness can name an incarnation that never existed.

Evidence: a one-stage Shape B exact witness binding `i=inc99`, with no restart record, produced `REACHED 1/1 (control n/a)`.

Suggested fix: a) Check incarnation existence independently of trace position, then require positions for checks of temporal validity.

**8. Criticality: medium - Persisted guard references are trusted again after modification. SHOULD FIX.**

Status: FIXED (reviewer verification, 2026-10-08). `Synthesis.seal` restores persisted baseline files, written copies, the test inventory and instrumentation diff from memory, then rewrites `state.json`. It runs after agent execution and when synthesis exits, including late replay/gate completion and caught interruption. `load_tests` fails closed without `tests.json`. A fresh evaluator passed 13 focused cases, including both original evidence cases and independent late replay/gate restoration, interruption and subsequent resume checks. The truncated-log variant was already resolved by finding 2; this historical overlap does not represent an outstanding defect. The original PARTLY FIXED triage is therefore recorded as operationally FIXED.

Location: `statelens/scripts/statelens.py`, `Synthesis.load_baseline`, `load_campaign`, `save_state`, `own`, and `gate`.

In-memory copies protect the current invocation, but edits to persisted baseline files, `instrumentation.diff`, or the campaign test log survive and are trusted by later invocations. Campaign data is outside ordinary source-tree comparisons.

Evidence: changing a saved baseline during a vetoed attempt left the restored checkout unable to resume. Separately, truncating the test log caused a later `--redo` gate to accept a missing originally passing test. These require modification of campaign records, so their severity is lower than finding 2's ordinary output-format trigger.

Suggested fix: a) Verify and restore trusted persisted inputs after agents run and during unwind; persist and validate the original passing-test inventory rather than deriving it anew from a mutable log.

**9. Criticality: medium - Guard restoration changes the saved version of a stray failure. SHOULD FIX.**

Status: ALREADY FIXED (2026-10-08). HIGH fix 3's rework of version saving fixed it: when an agent run leaves a stray failure, `Synthesis.attempt` (`statelens/scripts/statelens.py`) calls `keep_version` right after `sweep`, before guard 2's `script_files(restore=True)`, and `Synthesis.preserve` likewise keeps the version before it restores, so `version.diff` and `version/` hold the tree the agent returned, its temporary `[[bin]]` block included. The reviewer's `tss_lifecycle_guard_restore.py` passes unchanged; the separate interruption-during-sweep case is V2 in the fix-verification checkpoint.

Location: `statelens/scripts/statelens.py`, `Synthesis.attempt`, `script_files`, and `keep_version`.

A stray failure's source snapshot is captured after guard 2 restores script-owned files. If an attempt leaves its temporary scaffold manifest entry and a crash artifact, the preserved version no longer describes the build configuration present at the failure.

Evidence: the preserved diff contained the scaffold module and thin target but omitted the temporary `[[bin]]` entry restored by the guard.

Suggested fix: a) Snapshot the agent-returned tree before any restoration and associate that snapshot with stray failures, while continuing to veto execution of that version.

**10. Criticality: medium - Archived replay commands point at the old live directory. SHOULD FIX.**

Status: FIXED (2026-10-08). The new `Synthesis.archive` (`statelens/scripts/statelens.py`), used by `redo_cards` and by `synthesize` for an attempt directory left without a report, moves a card's outputs to `TS-NNNN.<stamp>*` and rewrites `/reach/TS-NNNN/` to `/reach/TS-NNNN.<stamp>/` in the moved report and its attempts' `replay.txt` and `interrupted.txt`, and `check_scaffold` no longer renames an earlier revalidation directory that a report names but writes the new replays to `<tag>.<stamp>/` (`entry["replays"]`, printed by `restate`). Regressions: `Synthesize.test_a_redo_moves_the_crash_files_and_the_lines_that_name_them`, `test_an_earlier_revalidation_directory_stays_where_reports_name_it` and the extended `test_an_interrupt_keeps_a_failed_replay_and_its_whole_version` pass, and so does the reviewer's `test_archived_replay_command_still_names_its_crash`. An archived `run` or `replay` line still needs its `version.diff` applied first, since the scaffold then holds the replacement (SPEC 18.11).

Location: `statelens/scripts/statelens.py`, `Synthesis.redo_cards`, `handover`, and `write_report`.

`--redo` renames a card's output directory, but archived reports and replay commands retain absolute paths under its former location. They no longer identify the preserved crash input.

Evidence: after archiving a crashing version and successfully replacing it, the old crash existed under the timestamped directory while its command named a missing file under the live directory.

Suggested fix: a) Make archived artifact references relative to their archive, or rewrite saved commands when moving outputs. Test that every archived command still resolves its input.

**11. Criticality: medium - Redo leaves old fuzz-package crash artifacts associated with the replacement scaffold. SHOULD FIX.**

Status: FIXED (2026-10-08). `redo_cards` (`statelens/scripts/statelens.py`) now moves each `<package>/artifacts/*_<module>_statelens/` of the undone card to `TS-NNNN.<stamp>/artifacts/`, with a console line, and leaves the corpus, whose inputs still seed the replacement; SPEC 18.6.2 now states what PRD R-TS-SYN-2 already required. Regressions: `Synthesize.test_a_redo_moves_the_crash_files_and_the_lines_that_name_them` passes, and so does the reviewer's `test_redo_archives_fuzzer_crash_artifacts`.

Location: `statelens/scripts/statelens.py`, `Synthesis.redo_cards`, `strays`, and `sweep`.

Redo moves reach outputs but leaves `<package>/artifacts/<scaffold>/crash-*` in place. The next attempt treats them as preexisting, so they remain beside the replacement version rather than the version that produced them. R-TS-SYN-2 explicitly includes scaffold crash files in the outputs to move.

Evidence: a fixture's old artifact remained in the live package artifact directory after successful `--redo`.

Suggested fix: a) Archive selected scaffolds' existing artifact directories together with their source versions before regeneration.

**12. Criticality: medium - Executable lookup ignores `CARGO_TARGET_DIR`. SHOULD FIX.**

Status: FIXED (2026-10-08). `fuzz_binary` (`statelens/scripts/statelens.py`) now looks only in `$CARGO_TARGET_DIR/<host>/release/` when the variable is set, a relative value taken from the checkout where the build runs, so a stale binary in a default directory is never taken, and otherwise in the two default directories, as before. Regressions: the new `FuzzBinary` tests, `Synthesize.test_a_build_in_cargo_target_dir_is_found` and the reviewer's `test_real_cargo_build_in_custom_target_dir_is_located` pass, and a real `cargo fuzz build` with the pinned nightly and a relative `CARGO_TARGET_DIR` is found; `coverage_binary` still ignores the variable and is a plan follow-up.

Location: `statelens/scripts/statelens.py`, `fuzz_binary` and `Synthesis.build`.

The executable lookup searches hardcoded workspace/package target directories instead of Cargo's configured output directory, although that configuration is supported in the documentation.

Evidence: a real no-op fuzz target built successfully into a custom target directory using the pinned nightly. Its executable existed there, but `fuzz_binary` returned `None`; the orchestration fixture reported `NOT BUILT`. From the lookup logic, an old executable in a default directory could also be selected; that stale-executable variant was not executed.

Suggested fix: a) Resolve the effective Cargo target directory or consume the current build's artifact path, and bind replay to that build's executable.

**13. Criticality: medium - Clean reports success while leaving generated Rust that blocks the next campaign. SHOULD FIX.**

Status: FIXED (2026-10-08). `clean_plan` (`statelens/scripts/statelens.py`) now also deletes the files git ignores under each `target_states/` (`scaffold_dirs()`), listed as `delete` lines in the preview, and `cmd_clean` reports a `target_states/` that remains as a difference (exit 1), on a repeated clean too (the empty-directory case, V3 in the fix-verification checkpoint). Regressions: `Cleaning.test_what_git_ignores_under_target_states_is_deleted` and `Cleaning.test_a_target_states_directory_left_is_reported` pass, and so does the reviewer's `test_clean_removes_ignored_rust_left_by_interrupted_synthesis`. The trigger was wider than stated: a caught Ctrl-C already removed ignored `.rs` files and only a kill left them, but any ignored non-Rust file there, such as a `.DS_Store` or agent scratch, survived every restore and clean.

Location: `statelens/scripts/statelens.py`, `clean_plan`, `clean_scope`, `cmd_clean`, `Campaign.check_preconditions`, and `Synthesis.ignored_sources`.

An interrupted synthesis can leave Rust under a git-ignored directory such as `src/target_states/target/mod.rs`. Clean removes ordinary scaffold files but misses this source and leaves `target_states/`, which the next campaign rejects.

Evidence: clean returned `0`, the ignored file survived, and the next campaign precondition returned `2` because `target_states/` existed.

Suggested fix: a) Include the narrowly scoped ignored-source inventory already used by synthesis, and verify that cleanup leaves no generated directory that blocks reuse.

**14. Criticality: medium - Diagnostic reads can clone a full 64 MiB trace with reporting disabled. SHOULD FIX.**

Status: FIXED (2026-10-08). In `statelens/runtime/target_states.rs`, the trace lines of a miss (`settle`) and the handoff's `next=` lookup (`Stages::handoff`) now read the trace only under `reach()`, so nothing is copied with `STATELENS_REACH` unset; the suggested bounded APIs were not added, since only reach replays and the operator's crash replays print these lines. Regressions: the helper self-test `imp::tests::test_lines_that_do_not_print_read_no_trace` passes, and the reviewer's `allocation.rs`, rebuilt against the live helper, now peaks at 96 bytes for a miss and for a handoff with reporting off (67108864 with `STATELENS_REACH=1`, as intended).

Location: `statelens/runtime/target_states.rs`, `settle` and `Stages::handoff`; `statelens/runtime/statelens.rs`, `observations`.

The helper clones an entire trace suffix before limiting it to 64 diagnostic entries or searching for the first matching observation. These operations also run when `STATELENS_REACH` is unset, adding avoidable allocation to ordinary fuzz inputs.

Evidence: allocator instrumentation measured a `67,108,864`-byte allocation in each path at `TRACE_CAP`, while the original trace remained allocated.

Suggested fix: a) Skip reporting-only work when reporting is disabled. b) Use bounded snapshot and first-match APIs when reporting is enabled.

**15. Criticality: medium - Prescribed setup order creates construction witnesses before positions are enabled. SHOULD FIX.**

Status: FIXED (2026-10-08). Both Shapes and the Knobs section of `prompts/synthesize.md` now split and pick the knobs, call `Stages::new` and `Stages::budget`, and only then pin fields or perform witnessed setup, saying that before `Stages::new` `Witness::act` takes position 0; the `Witness::act` doc in `statelens/runtime/target_states.rs`, SPEC 18.7 with its 13.21 copy, and PRD R-TS-SC-2 agree, and no helper code changed. No suite test covers prompt text: the reviewer's `pin_before_new` fixture still prints `seq=0`, as now documented, while the same scaffold in the new order prints `seq=1 read=1` and the script gives REACHED 2/2, and `just check-prompts` reports 0 problems.

Location: `statelens/prompts/synthesize.md`, Shapes and Knobs; `statelens/runtime/target_states.rs`, `Stages::new` and `Witness::act`.

The prompt orders pinning before opening stages, but a witnessed pin/setup action performed before `Stages::new` runs with observation disabled. `Witness::act` then obtains position zero, which cannot establish an ordered history.

Evidence: the prescribed order emitted a construction witness with `seq=0 read=0`; the actual parser downgraded it to `unverifiable (no position)` despite a valid subsequent Shape A handoff.

Suggested fix: a) Order instructions as split/pick knobs, open stages and check budget, perform witnessed setup actions, then enter the base.

**16. Criticality: medium - Generic oracle instructions do not fit several recommended Marshal bases. SHOULD FIX.**

Status: FIXED (2026-10-08). `prompts/synthesize.md` now takes the runtime deadline from the base (passing `Duration::MAX` for a base without one) and leaves Shape A's oracles inside the base's entry, sending a History they would not measure to Shape B, and new "Progress and deadline" bullets in `prompts/subsystems/marshal-synthesize.md` and `simplex-synthesize.md` give each base's deadline and its own liveness measure counted from the handoff (the simplex rule was made per driver after verification), with the marshal fault phase corrected to 12 s in the scenario-prefix runner and 30 s `FAULT_PHASE` in the end-to-end runner; SPEC 18.7, its 13.21-13.23 copies and PRD R-TS-SC-5 match. No suite test covers prompt text: a verifier checked the rules against the base code, and `just check-prompts` reports 0 problems.

Location: `statelens/prompts/synthesize.md`, Oracles and Handoff and recovery; Marshal end-to-end input/scenario implementations and `consensus/fuzz/marshal/src/marshal/store.rs`.

The shared prompt unconditionally prescribes `input.required_containers` and `fuzz_runtime_timeout`. `MarshalTwinsInput` uses `trailing_blocks`; the scenario input and actor-store input lack the prescribed field. The scenario's actual progress oracle uses each node's GST height. Also, a Shape A check performed after a base entry returns cannot rebase a liveness wait that already completed inside that entry.

Evidence: static comparison of the prompt with the advertised inputs and continuation implementations establishes the incompatible instructions; no model-generated campaign was used to claim an observed synthesis failure.

Suggested fix: a) Specify progress and deadline rules per base/input type, preserving its operation oracles. Require an appropriate shape where continuation must begin from a live handoff.

**17. Criticality: medium - Marshal's advertised case selector does not fix the selected history. SHOULD FIX.**

Status: FIXED (2026-10-08). The "Shape A first" bullet of `prompts/subsystems/marshal-synthesize.md` now says the `*_twins_split_header` targets draw their Twins case from the stream `raw_bytes` seeds, so no field pins it and a History about it takes Shape B, a fixed case needing a marked constructor for the private `mocks::twins::Scenario` and `RoundScenario`; SPEC 18.7 (Shape A examples and the Marshal bullet) and its 13.23 copy match. No suite test covers prompt text: a scratch crate that mirrors the call chain gave 7 distinct cases from 8 tapes with `rounds` and `case_selector` fixed, and `just check-prompts` reports 0 problems.

Location: `statelens/prompts/subsystems/marshal-synthesize.md`, Shape A first; `consensus/fuzz/marshal/src/marshal/end_to_end/twins/mod.rs`; `consensus/fuzz/core/src/lib.rs`, `run_twins_with_backend`.

The prompt says `rounds` and `case_selector` fix the Twins case. The focused entry supplies `raw_bytes` as entropy, and the core samples cases from that entropy before the backend applies the selector. Remaining bytes can therefore change the selected history while those fields stay fixed.

Evidence: the actual entry-to-core-to-selector call chain contradicts the instruction. The Simplex subsystem prompt already describes its analogous limitation.

Suggested fix: a) Describe the sampling dependency and use an explicit fixed scenario or Shape B when the card requires an essential history that input fields cannot fix.

**18. Criticality: medium - Example cards omit identity bindings needed by their checks. SHOULD FIX.**

Status: FIXED (2026-10-08). `target-states/marshal/TS-0001.md` E5 now declares `p1 as E2` and `TS-0002.md` E4 declares `B as E1`; TS-0001's knob row was corrected as well, since with E6 first the voter drops the stale rejection and R's nullify vote comes from the certification timeout (checked with a probe test of the voter), and the SPEC 18.3 copy matches. Regression: `TargetStateLint.test_example_cards_bind_what_their_checks_name` passes, and both cards lint clean.

Location: `statelens/target-states/marshal/TS-0001.md`, History E5; `statelens/target-states/marshal/TS-0002.md`, History E4; `statelens/scripts/statelens.py`, `history_parse` and `witness_rule`.

TS-0001's E5 check refers to parent `p1` but omits `p1 as E2` from its entity list. TS-0002's final check refers to peer `B` but omits `B as E1`. The validator checks declared identities, leaving those relations outside its binding checks. TS-0001 is also the extraction prompt's example.

Evidence: two focused assertions over the actual parsed cards confirmed both missing references.

Suggested fix: a) Add the missing entity references and regression assertions for the cards' intended cross-stage bindings.

**19. Criticality: medium - Oracle preservation conflicts with the blanket panic prohibition. SHOULD FIX.**

Status: FIXED (2026-10-08). The Missing capabilities rule of `prompts/synthesize.md` now covers only the prefix and witness code a scaffold writes, and says that code copied verbatim from the base, and every oracle, keep their panics, since after the handoff a miss records nothing; SPEC 18.7 with its 13.21 copy, and PRD R-TS-SC-7, match. No suite test covers prompt text: a stub driver against the live helper showed that misses after the handoff print nothing, and `just check-prompts` reports 0 problems.

Location: `statelens/prompts/synthesize.md`, Shapes, Oracles, and Missing capabilities; `consensus/fuzz/simplex/src/lib.rs`, the `run_standard_once` continuation.

The prompt requires copied drivers and inherited oracles to remain verbatim, but also prohibits every SUT-dependent `unwrap`/`expect` in scaffold code and asks for a miss instead. The actual continuation contains `monitor.recv().await.expect("event missing")`. Copying this oracle violates the blanket instruction; replacing its failure with a stage miss weakens the inherited oracle.

Evidence: this is a concrete conflict between prompt instructions and a recommended base, verified statically. It is not a claim that a generated scaffold has already weakened that oracle.

Suggested fix: a) Restrict the no-panic rule to newly introduced prefix and witness code, and explicitly preserve inherited oracle failures.

**20. Criticality: medium - Abandoned scaffold files can produce a successful handover after a failed resumed build. SHOULD FIX.**

Status: FIXED (reviewer verification, 2026-10-08). `Synthesis.keep_pending` persists each card's original `S0` before agent execution, and `recover`, first in `run_cards`, restores an unfinished card before the next snapshot and removes its module declaration. Five fresh focused checks pass: failed resume and a subsequent skipped invocation return 3 without the abandoned target; when another card succeeds, only that card is handed over. The earlier last-build check had already prevented one manifestation, but pending-snapshot recovery now fixes the original cause. Report-based selection is unnecessary for this specific cause. The original PARTLY FIXED triage described historical overlap, not a remaining operational defect; finding 4's interrupted-undo case remains separate.

Location: `statelens/scripts/statelens.py`, `Synthesis.finish`, `Synthesis.run`, and `select_scaffolds`.

After an unclean termination, generated files can become part of the next invocation's starting snapshot. If the resumed build fails, restoration retains those files and the card reports `NOT BUILT`. Final selection then rediscovers the leftover thin target and advertises it as runnable. This requires an unclean termination; ordinary caught KeyboardInterrupt follows a different cleanup path.

Evidence: an isolated regression produced one failed build, a `NOT BUILT` report, exit `0`, a handover command, and a surviving thin target with no corresponding manifest target. Cargo subsequently rejects that missing target.

Suggested fix: a) Recover the pending card's original snapshot before adopting abandoned files. b) Select final handovers from validated reports and manifest state, excluding cards that just ended `NOT BUILT`.

**Validation and review coverage**

- `just check-scripts`: 375 tests passed.
- `just check-invariants`: 55 files, zero problems.
- `just check-prompts`: zero problems.
- `git diff --check`: passed.
- Runtime validation included isolated compilation of the unchanged helper/templates, 17 non-provider runtime tests, scalar witness fixtures, and allocation measurements. External dependency/provider integration was stubbed in these isolated fixtures.
- Additional expected-safe regression assertions failed on the behaviors described above. Lifecycle fixtures used temporary repositories and simulated build/replay results; findings 4 and 12 additionally used real compiler/build checks. Finding 2 used real nextest rendering from an arithmetic-only test.
- Reviewed all 23 prompt files and their rendering paths, both templates, four supplied cards, changed orchestration/runtime/recipe/test code, and the relevant base interfaces.

Fresh-context audit rounds:

| Round | Independent auditors/evaluators | Result |
| --- | --- | --- |
| 1 | Lifecycle, witness soundness, runtime, prompts, integration | Initial findings and regression evidence |
| 2 | Lifecycle evaluation, soundness evaluation, integration/prompts | Confirmed earlier high findings; added the high nextest gate finding; downgraded persisted-reference concern to medium |
| 3 | Gate/lifecycle evaluation and residual semantics audit | Confirmed gate finding; added finding 20; no new critical/high finding |
| 4 | Independent workflow and semantics evaluators after the intermediate report | Confirmed the findings and their severities; no new critical/high finding and no report corrections |

The review stopped after the final fresh-context evaluation round added no critical/high finding, meeting the requested stopping condition. All 39 reviewed input files, HEAD, and the tracked TSS diff still matched the initial snapshot at the end of review. This is a review conclusion, not a proof that no further defect exists.

The committed synthesis tests mock the agent, build, executable, replays, and gate. Existing recipe tests substitute command tools. Passing these tests does not establish a real generated Simplex/Marshal campaign or the complete end-to-end acceptance procedure. No such campaign was executed in this review.

The documented limits concerning wrapper placement, the truth of a harness action, unstamped base restarts, and semantic witness provenance were not promoted into additional findings. The listed findings concern implementation behavior or concrete prompt/base conflicts beyond those accepted limits.

**Snapshot identifiers**

SHA-256 of `git diff -- statelens/` at review start: `65d79a408679522ac5388c294ae5b64a2cc59e41e6f39ba1bfdf559107781ad7`.

| Reviewed file | SHA-256 |
| --- | --- |
| `statelens/scripts/statelens.py` | `e49b880e38e88682b3bcd4d3ad8c6dfa10364354e31d9635a2657928ca823a23` |
| `statelens/scripts/test_statelens.py` | `a54a23903bf8af184ae20031bc4ad0ba7d3a835093415c5796ef4d1821a1e130` |
| `statelens/runtime/statelens.rs` | `5e5fbc874f42a9bd849dcae0b0e6f38ca7842712eb937ef7eea97971e5d3c038` |
| `statelens/runtime/target_states.rs` | `80625a021065af0688e06e686716944544c714aa0d3d50f3a5fc29059ede8917` |
| `statelens/prompts/synthesize.md` | `783639b54b53f8b931c32a262092e09c8f55eb3b84d10f5b392b7f4f21398f63` |
| `statelens/prompts/subsystems/marshal-synthesize.md` | `c7d92d07fa89a73feea978df920afda812b2024a09f3484d7b6fa2d7503df737` |
| `statelens/target-states/marshal/TS-0001.md` | `9b42c6f65050b4f135f9ed4bc3562033737e422c4c437ad8bee851f79e271f53` |
| `statelens/target-states/marshal/TS-0002.md` | `a9d44f33f6bddfc486c4ff22f372c53c23a55c4e34cc1e1d6cc1290125f1bc0b` |

**Regression evidence retained locally**

These temporary audit fixtures are outside the repository and were not added to its test suite. They use benign scalar states, temporary repositories, mocked replay outcomes, or toy compiler/test projects. Their expected-safe assertions fail on the reported defects; relevant passing controls are described above. Static prompt findings are grounded in the named source interfaces.

| Findings | Evidence |
| --- | --- |
| 1, 6, 7 | [/private/tmp/tss_r1_witness_review/test_witness_review.py](/private/tmp/tss_r1_witness_review/test_witness_review.py), with the scalar Rust source and captured traces in the same directory |
| 2 | [/private/tmp/tss-r2-nextest-layout/check_format.py](/private/tmp/tss-r2-nextest-layout/check_format.py) and [/private/tmp/tss-r2-integration-regressions.py](/private/tmp/tss-r2-integration-regressions.py) |
| 3, 8, 10, 11 | [/private/tmp/tss_lifecycle_review.py](/private/tmp/tss_lifecycle_review.py) |
| 4, 8 | [/private/tmp/tss_lifecycle_crosscard.py](/private/tmp/tss_lifecycle_crosscard.py) |
| 5, 14, 15 | [/private/tmp/statelens-r1-runtime-_ezb3ovp/check_contract.py](/private/tmp/statelens-r1-runtime-_ezb3ovp/check_contract.py), with `driver.rs`, `allocation.rs`, and `pin_before_new.rs` in the same directory |
| 9 | [/private/tmp/tss_lifecycle_guard_restore.py](/private/tmp/tss_lifecycle_guard_restore.py) |
| 12, 13 | [/private/tmp/tss-r1-integration-regressions.py](/private/tmp/tss-r1-integration-regressions.py); actual custom-directory Cargo build under `/private/tmp/tss-r1-cargo-layout-qitvudi6/` |
| 20 | [/private/tmp/tss-r3-abandoned-scaffold.py](/private/tmp/tss-r3-abandoned-scaffold.py) |
