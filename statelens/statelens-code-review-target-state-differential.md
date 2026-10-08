**Target-State Synthesis differential-test review**

Review date: 2026-10-08. Reviewed the uncommitted differential-testing changes against HEAD `392b116687bea3085c5c074aa05618e630c1f101`, including the new crate and shell script. Original findings: **4 medium and 2 low**. Fix verification leaves **one medium issue open under finding 1**, and adds **one low residual, finding 7**. No critical/high issue was substantiated in either review.

Four fresh-context auditors examined scenario/prefix correspondence, the state digest, runner/verdict integration, and visibility/documentation. Two further fresh-context evaluators independently assessed the candidates and looked for additional critical/high issues; neither established one. Only this report was added. No implementation, tests, cards or templates were edited by the reviewers.

The implementation compares a projection of **settled state after `finish`**, using hand-written TSS prefixes and one canonical byte stream. It does not establish exact state equality at the handoff mark or validate agent-generated scaffolds. Those limits are documented. The fixes now enforce execution of the 30 required cases, reject the reproduced canonical crashes and missing-digest failures, and strengthen both disputed witnesses. A verdict caused only by a defective control can still falsely count as detection of a negative.

**Fix verification (2026-10-08)**

Four new fresh-context auditors reviewed runner behavior, scratch ownership, witnesses and documentation. Two new fresh-context evaluators independently checked the remaining candidates and searched for critical/high issues. The reviewers changed only this report. Author status paragraphs and original finding descriptions below are retained as history; the reviewer status table and this verification section describe the current tree.

| Finding | Criticality | Status | Summary |
| --- | --- | --- | --- |
| 1 | medium | PARTIALLY FIXED (verified) | Canonical failures are rejected; control-only invalidity can still falsely count as detection. |
| 2 | medium | FIXED (verified); residual in 7 | Missing, empty, duplicate and moved required cases are rejected. |
| 3 | medium | FIXED (verified) | Scratch ownership is isolated per invocation. |
| 4 | medium | FIXED (verified) | TS-9005 observes its receiver before reporting pending. |
| 5 | low | FIXED (verified) | TS-9006 preserves E2's observed registration count at E4. |
| 6 | low | FIXED via documented exception (verified) | Excerpts are current; the fixture-location lint exception is explicit. |
| 7 | low | OPEN | Additional nested tests are filtered out before inventory comparison. |

Findings 3-5 are confirmed by source inspection and independent harmless checks. Command stubs exercised overlapping scratch runs, failed worktree creation/removal and interrupts; each cleanup targeted its own unique directory, and unrelated sentinels survived. Scalar checks through the real validator reject ready/closed/absent receivers at TS-9005 E2 and a TS-9006 registration increase from 1 to 2, while accepting unchanged counts. These checks validate the predicates and runner behavior; they do not recertify a protocol execution.

Finding 6 is resolved through the documented fixture exception, corresponding to the original alternative b, rather than new lint-location support. Explicitly linting all seven cards still exits 3 with seven rule-1 location errors; their excerpts are current and the other rules pass. SPEC 18.10.1 and the differential README accurately document this. The latest claim that lint now accepts `differential/cards/` does not match the inspected tree: `lint_file` has no such exception. Default lint's zero-problem result does not cover these fixtures.

**1. Criticality: medium - Invalid negative executions count as successful detection. SHOULD FIX.**

Author status: FIXED (2026-10-08). `statelens/scripts/differential.sh`, `VERDICT_SHAPE` and the `neg_*` branch of the result loop: a negative counts as caught only from a replay that exited 0 with a `digest-equal` line of `true` or `false` and a verdict the validator computed (`REACHED|UNVERIFIED|PARTIAL|UNREACHED k/n`, annotated or not); anything else is `(ERROR)` and fails the run, and equal digests with a REACHED verdict, annotated or not, stay `(NOT CAUGHT)`. Verified by grep of the branch and by the verifier's run with a validator exception injected on `neg_ts9007_finalization_to_c` (`Traceback ... (ERROR)`, `differential: FAILED`, exit 1) while the genuine 30-test run passes; suggestion b (asserting each negative's documented signal) was not taken.

Reviewer validation: **PARTIALLY FIXED; medium, SHOULD FIX remains.** The reproduced canonical crashes, missing digests, control crashes and early validator exceptions now fail. However, `control_status` returns `vacuous` for a control that exits 0 without its `done` line, and `reach_verdict` turns an otherwise fully accepted canonical report into `UNVERIFIED n/n`. The runner accepts that as a caught negative even with equal digests. A weak control can produce the same acceptance without any canonical rejection.

Independent checks used identical canonical scalar evidence with every stage held, a valid handoff, exit 0 and `digest-equal=true`. A valid control gave `REACHED 5/5` and `(NOT CAUGHT)`. Removing only the control's `done` or `withheld` line gave `UNVERIFIED 5/5` and acceptance; a weak control gave `UNVERIFIED 5/5 (weak)` and acceptance. Canonical problems and rejected witnesses were empty in every case. An unchanged full-runner fixture under Bash 3.2 likewise printed PASSED with an incomplete control and `UNVERIFIED 4/4`.

This requires a negative-specific control defect while the canonical run shows no detected deviation. Shared control defects should also fail corresponding positive cases. It is a weakness in the negative acceptance contract, not evidence that the author's actual protocol run falsely passed. SPEC 18.10.1 step 6 currently permits this behavior, so the code and specification need the same correction.

Suggested remaining fix:

a) With equal digests, require rejection attributable to the canonical stages. Under the current validator semantics, reject control-only `UNVERIFIED n/n`: every canonical stage held, so this verdict alone establishes no canonical deviation.
b) Expose structured canonical rejection and control status, or assert each negative's documented signal, rather than interpreting every computed non-REACHED verdict as detection. Do not require a valid control unconditionally: TS-9007's wrong-node negative can already miss a canonical stage and have a vacuous control.

Current evidence: [independent real-validator results](/private/tmp/tss-control-independent-5xfys9sx/results.json), [canonical/control decomposition](/private/tmp/statelens-runner-fix-audit-fa57m0j9/scalar-intermediate.json), [full-runner incomplete-control output](/private/tmp/statelens-runner-fix-audit-fa57m0j9/negative_control_incomplete/stdout.txt), and [retained command-stub harness](/private/tmp/statelens-runner-fix-audit-fa57m0j9/audit.py).

Original finding analysis follows.

Location: `statelens/scripts/differential.sh`, `replay`, the `reach-verdict` invocation and the `neg_*` result branch.

The negative branch fails only when `digest-equal=true` and the verdict is an unannotated REACHED. The validator's exit status is discarded with `|| true`. Missing digest output, a replay crash, a control-run failure, an empty verdict or a validator exception therefore all count as a caught negative. These outcomes do not establish that the intended state comparison or witness rule detected the deliberate deviation.

A command-only fixture executed the unchanged script with all 30 current test names. Its 24 positives passed their stub checks, while all six negatives exited 101, emitted no digest and received `CRASH / VIOLATION`. The script still exited 0 and printed PASSED. A global validator outage would fail the positives; the defect concerns errors affecting a negative case. This does not establish that the author's successful protocol run encountered such an error.

Suggested fix:

a) Require successful expected replay completion, valid digest output and a successfully parsed verdict before judging detection. Distinguish the validator's expected non-REACHED exit from an invocation/parser error.
b) Assert each negative's documented signal. Wrong-node certificate and armed-delivery controls should demonstrate unequal digests with REACHED; stale-handoff and swapped-order controls should demonstrate their specific rejection. If an assertion failure is an intended oracle, check its expected location/message explicitly.

Evidence: [retained negative captures](/private/tmp/tss-runner-audit-wlqs06nc/negative_crash/scratch/differential-logs/), [example verdict](/private/tmp/tss-runner-audit-wlqs06nc/negative_crash/scratch/differential-logs/neg_ts9001_dropped_arm.verdict), and [Cargo stub encoding exit 101](/private/tmp/tss-runner-audit-wlqs06nc/negative_crash/bin/cargo). The auditor's captured full-run result was `negative_crash status=0 inventory=30 summary=differential: PASSED`; its harness ran inline, so complete stdout was not retained. An independent evaluator confirmed the branch logic. No protocol execution was involved.

**2. Criticality: medium - Successful empty or partial discovery can report PASSED. SHOULD FIX.**

Author status: FIXED (2026-10-08). `statelens/scripts/differential.sh`, `EXPECTED_TESTS` (the 30 names of `src/tests.rs`) and a sorted `diff` against `-- --list` right after the `tests=$(...)` assignment: a missing, extra, duplicate or nested name prints the diff (kept in `logs/tests.diff`) and exits 2 before any replay, and `printf '%s\n' ${rows[@]+"${rows[@]}"}` removes the bash 3.2 empty-array error. Verified by grep and by the verifier's run with `neg_ts9002_stale_handoff_read` deleted from `src/tests.rs` under bash 3.2 (exit 2, `< neg_ts9002_stale_handoff_read`, zero replays, no PASSED); no command-stub regression test was added, since the script has no test suite.

Reviewer validation: **FIXED for the original medium failure.** Independent full-script stubs reject empty discovery, a missing required negative, duplicates, an extra flat name and a required test moved into a nested module before replay. The broader claim about every extra/nested name is inaccurate; additional nested tests remain silently excluded, recorded separately as low finding 7.

Location: `statelens/scripts/differential.sh`, the `tests=$(cargo ... --list | sed ...)` assignment and result loop.

The script filters discovery to names matching `tests::[a-z0-9_]*` and never checks the resulting inventory against the prescribed cases. A successful empty listing skips every replay, leaves `failed=0` and prints PASSED. Moving a test to a nested module can silently exclude it; losing only a negative can remove its protection while the remaining tests still pass.

The unchanged script exited 0 with an empty stub listing and printed PASSED. All 24 positives and six negatives are present and match discovery in the current source, so this is a regression-detection defect, not a claim that the current successful run omitted them. A failing Cargo discovery command itself is caught by `pipefail`.

Suggested fix:

a) Validate the exact expected test-name set, rejecting missing, unexpected and duplicate entries before replay.
b) Add command-stub regressions for empty, partial, nested-name and failed discovery. Require the required cases rather than relying only on a nonzero count.

Evidence: [empty-inventory fixture commands](/private/tmp/tss-runner-audit-wlqs06nc/empty_inventory/bin/). The captured result was `empty_inventory status=0 inventory=0 summary=differential: PASSED`; no per-test logs exist because none ran. Independent scalar discovery checks confirmed that empty and nested-name listings select zero cases.

**3. Criticality: medium - Scratch cleanup can remove another invocation's worktree or an unowned directory. SHOULD FIX.**

Status: FIXED (2026-10-08). `statelens/scripts/differential.sh`: `RUN=$(mktemp -d "$SCRATCH/run.XXXXXX")` with `WT=$RUN/wt-diff` and `LOGS=$RUN/logs` replaces the fixed paths, the startup log deletion and the startup `cleanup` of an existing `wt-diff` are gone, and the EXIT trap's `cleanup` removes only the worktree this run created (old `run.*` directories with their logs are the operator's to remove). Verified by grep and by the verifier's two concurrent runs in one scratch directory (both worktrees registered at once, both PASSED with 30 rows, zero worktree registrations left) and a pre-existing `<scratch>/wt-diff` sentinel that survived a run.

Location: `statelens/scripts/differential.sh`, `SCRATCH`, `WT`, `LOGS`, `cleanup` and the startup existing-directory check.

Every invocation uses `<scratch>/wt-diff` and `<scratch>/differential-logs`. Startup deletes old logs and calls `cleanup` whenever the worktree path exists. `cleanup` force-removes it through Git, falling back to recursive deletion when Git refuses, without checking whether this invocation created or owns it. Concurrent runs can remove each other's live build tree and evidence. An unrelated directory specifically occupying that scratch child also reaches the deletion fallback.

A harmless full-script fixture made Git refuse removal of an unrelated fixture directory. A recording-only `rm` stub captured recursive deletion of that directory at startup and EXIT; its sentinel survived because deletion was stubbed. The original checkout is unaffected. The dedicated scratch-child prerequisite supports medium severity rather than a broad high-severity repository-data-loss claim.

Suggested fix:

a) Allocate a unique scratch/worktree/log directory per invocation and register cleanup only after successful creation.
b) Clean only a directory whose ownership was established by that invocation. Refuse an unowned existing path instead of recursively deleting it; retain a clear per-run log location.

Evidence: [full-script command capture](/private/tmp/tss-cleanup-fullscript-audit-5yf70qw7/calls.jsonl), [stdout](/private/tmp/tss-cleanup-fullscript-audit-5yf70qw7/stdout.txt), and [unrelated fixture sentinel](/private/tmp/tss-cleanup-fullscript-audit-5yf70qw7/scratch/wt-diff/unrelated-source.txt). No real worktree or user data was deleted in the check.

**4. Criticality: medium - TS-9005's pending witness observes a prefix-written string, not receiver readiness. SHOULD FIX.**

Status: FIXED (2026-10-08). `statelens/differential/src/cards/ts9005.rs`: the unconditional `verify=pending` stamp after `wrapper_verify` is gone, `e2_recorded` returns only the recorded `subscription` and `fetch_count` entries, and E2 then reads the held receiver once with `try_recv`, stamping `verify=pending` and holding E2 only on `TryRecvError::Empty`, while a verdict or a closed channel records it, sets `verify = None` and misses E2 (`the verification of d did not stay pending`). Verified by grep and by the verifier's wrong prefix that lets the verification resolve before E2 (old witness: `E2/5 held` with `verify=pending`; new: `E2 missed`, PARTIAL 1/5), and the four ts9005 tests stay REACHED 5/5 with equal digests in the procedure rerun.

Location: `statelens/differential/src/cards/ts9005.rs`, `prefix` and `e2`.

After obtaining the verification receiver, `prefix` unconditionally records `verify=pending`. E2 reads that entry, a subscription and a zero fetch count without inspecting the receiver. The card explicitly requires verification to remain pending at E2. A receiver already containing a verdict is compatible with the recorded evidence. E5 later consumes a true result, so eventual true verification/certification and equal settled digests cannot establish the historical E2 pending property.

A scalar fixture keeps receiver readiness separate from the recorded string and feeds the resulting synthetic entries to the real validator. The ready-receiver case is accepted as REACHED 5/5 with no rejection reasons. This confirms the observation gap; it does not demonstrate a production-protocol failure or an actual false-equal protocol run. TS-9006 already checks `try_recv() == Err(Empty)` for its analogous pending stage.

Suggested fix:

a) Inspect the receiver when E2's other conditions hold; reject ready/dropped outcomes and stamp pending only after observing `TryRecvError::Empty`.
b) Put the readiness observation in a dedicated wrapper and use that observation as E2's witness evidence.

Evidence: [scalar predicates and real-validator checks](/private/tmp/tss-actions-scalar-checks.py). The expected-correct rejection assertion fails. An independent evaluator confirmed that the final digest and reference scenario do not prove this added intermediate predicate.

**5. Criticality: low - TS-9006's final witness permits an increased registration count. CONSIDER.**

Status: FIXED (2026-10-08). `statelens/differential/src/cards/ts9006.rs`: `waiting(recorder, m, count)` takes `None` at E2 (`replica_nonzero`) and `Some(count)` at E4 (`replica_exact`), E2 stores its observed `subscription[B=1,m=..]` value in `registered` when it holds, and E4's handoff closure requires that value (`registered.as_deref()?`), so the control run misses E4 by construction; the refix also moved the `verify=pending` stamp from the call into E2's `try_recv` branch. Verified by grep and by the verifier's wrong prefix that registers a second wait after the drop (old: `E4/4 held` with `=2`; new: `E4 missed: not held at handoff`, PARTIAL 3/4), the four ts9006 tests staying REACHED 4/4 in the procedure rerun; suggestion b (the `subscriptions` total as a fifth E4 item) was not taken.

Location: `statelens/differential/src/cards/ts9006.rs`, `waiting` and `prefix`; reference `StandardVerifyMissingCandidateWaitsWithoutFetching::drive`.

The reference captures the subscription count before dropping the verify receiver and asserts equality after its barrier. E2 and E4 in the TSS prefix instead accept any nonzero per-digest subscription count. An increase from 1 before cancellation to 2 afterward satisfies E4, contradicting the card's unchanged-wait requirement and the prefix comment.

Synthetic scalar entries for that increase are accepted by the real validator as REACHED 4/4. The complete differential suite still detects a corresponding registration regression through the reference assertion on side A (both sides run the same system under test, so its regression shows in both digests); this is a local witness gap rather than an established false-equality defect.

Suggested fix:

a) Capture E2's registration count and require the same value inside E4's handoff closure.
b) Also preserve the reference's total-count equality check if the card intends to rule out any additional subscription.

Evidence: [scalar count-change check](/private/tmp/tss-actions-scalar-checks.py). The expected-correct rejection assertion fails; an independent evaluator confirmed the overall-suite protection and low severity.

**6. Criticality: low - Differential cards fail the full card lint they are documented to follow. SHOULD FIX.**

Status: FIXED (2026-10-08). Triage: PARTLY_VALID, since the docs claimed the 18.3 grammar, not lint-cleanliness, and only rules 1 and 11 failed, rule 1 by the documented location outside the card trees (the `9NNN` ids stay out of the registries' counter). Fix: `statelens.py excerpts` generated the `## Source excerpts` section of `differential/cards/TS-9001.md` to `TS-9007.md`, and SPEC 18.10.1 and `differential/README.md` state that lint reaches the cards only when named and reports their location (rule 1) and nothing else. Verified today from `statelens/`: `excerpts --check` 0 of 7 out of date and explicit `lint` of the seven cards 7 problems, all rule 1; not taken, as follow-ups in the plan: fixture-location support in `lint` (`statelens.py` has none) and a lint step in `differential.sh` (none).

Location: `statelens/differential/cards/TS-9001.md` through `TS-9007.md`; `statelens/differential/README.md`, Layout; SPEC 18.3, 18.10.1 and rule 11; `cmd_reach_verdict`.

The seven files are documented as cards in the SPEC 18.3 grammar, but all omit its generated Source excerpts. The full linter also does not recognize their fixture location. Explicitly checking these seven files returns exit 3 and **14 problems**: seven unsupported-location errors and seven missing-excerpt errors. The location outside the synthesis registries is intentional, but no fixture-specific lint support or documented reduced grammar exists.

Default invariant lint does not discover these files. `cmd_reach_verdict` calls `card_history`, checking the ID and History rather than the complete card, and the differential runner has no full card-lint gate. Thus the passing default lint and differential verdicts do not substantiate the stated full-card conformance.

Suggested fix:

a) Add narrowly scoped fixture-location support, generate the excerpts and explicitly lint these files in the procedure, while keeping them outside synthesis discovery and ID allocation.
b) Alternatively, specify the reduced fixture grammar and remove the full-conformance/lint-clean claim.

Evidence command, run from `statelens/`: `just check-invariants differential/cards/TS-9001.md differential/cards/TS-9002.md differential/cards/TS-9003.md differential/cards/TS-9004.md differential/cards/TS-9005.md differential/cards/TS-9006.md differential/cards/TS-9007.md`. Root execution and a fresh auditor's direct `lint_file` checks agree. All seven Histories and module control headers do parse.

**7. Criticality: low - Additional nested tests bypass the exact-inventory check. SHOULD FIX.**

Status: OPEN (fix verification, 2026-10-08).

Location: `statelens/scripts/differential.sh`, `tests=$(...)`, `EXPECTED_TESTS` and the sorted inventory comparison; SPEC 18.10.1 step 4.

The discovery parser accepts only names matching `tests::[a-z0-9_]*`. The inventory comparison therefore sees an already-filtered list. Adding `tests::nested::extra_test` alongside all 30 expected names leaves the compared list unchanged: the script runs only the original 60 canonical/control replays and prints PASSED, silently omitting the added test. This contradicts the stated exact-inventory guarantee.

The original 30 required names are protected. Moving a required case into a nested module removes its expected flat name and correctly fails, so this residual is low rather than a continuation of the original medium omission defect.

Suggested fix:

a) Compare all discovered fully qualified test names against a fully qualified expected inventory before removing any prefix.
b) Reject any discovered test entry the selection parser does not recognize, instead of silently discarding it.

Evidence: [30 required names plus one nested entry](/private/tmp/statelens-runner-fix-audit-fa57m0j9/inventory_extra_nested/config.json), [unchanged full-runner PASSED output](/private/tmp/statelens-runner-fix-audit-fa57m0j9/inventory_extra_nested/stdout.txt), and [case summary, including rejected inventory variants](/private/tmp/statelens-runner-fix-audit-fa57m0j9/summary.json). An independent evaluator confirmed the same behavior with a scalar discovery check. Cargo and protocol execution were stubbed.

**Original review coverage, successful checks and limits**

Static correspondence covers all six original scenario kinds, split into seven cards, with Deferred/Inline and both configurations: **24 positive pairs and six negatives**, not five. Side A calls the original `drive`; side B independently scripts the harness verbs. Shared setup and block/certificate helpers do not make that comparison vacuous. The setup matches the runner before engines, with the same forwarding wrappers installed on both sides. TS-9007 adds delivery waits beyond the reference's archive reads, further illustrating why post-settlement agreement does not prove identical handoff timing.

The nine Marshal Rust diffs contain visibility changes, two lint allowances and rustfmt reflows only. Root Cargo metadata excludes the differential crate and shim; production manifests and `consensus/src` are unchanged. Both imported runtime templates are byte-identical to HEAD. The extra `RecordingResolver::holding` visibility change that arrived during review was inspected separately and is also behavior-neutral.

The digest covers current blocks/certificates, per-node durable storage and a whole-storage audit. Its settling and mailbox reads are an observation procedure that permits progress and cleanup, not an untouched handoff snapshot. Live subscription details and wrapper gates are not fully represented. Armed payloads are reduced to presence and unread verdicts to queue length. Scalar collisions exist in those projections, but every successful reference leaves no armed payload, and the current retained delivery verdict comes from TS-9005's successful delivery. No supported false-equal prefix exploiting these omissions was established; they are recorded as limits, not additional confirmed findings.

Root checks: 43 `ReachCheck`/`ReachVerdictCommand` tests pass; prompt lint reports 0 problems; default invariant lint reports 68 files and 0 problems; `bash -n` and `git diff --check` pass. The explicit seven-card lint fails as described above. Command-stub runner checks and scalar/parser checks support the findings. The reported full 469-test suite, Marshal clippy/80 tests and full differential protocol run were not rerun by the reviewers. No protocol scenarios, fuzzers or protocol mutation experiments were executed during this review; the author's reported 24-pair runtime results are not independently recertified here.

**Fix-verification checks and limits**

Root checks repeated for this verification: `just check-scripts` (**469 tests passed in 316.721 seconds**), `bash -n`, `git diff --check`, prompt lint (0 problems), default invariant lint (68 files, 0 problems), and explicit excerpt freshness (0 of 7 outdated). Explicit seven-card lint has exactly seven rule-1 location errors, matching the newly documented exception.

Independent auditors also ran 43 focused parser/verdict tests, real-validator scalar checks, and command-stub fixtures for the unchanged runner under Bash 3.2. [Scratch ownership checks](/private/tmp/tss-cleanup-fix-audit-g0y799mt/results.json) cover overlapping invocations and failure/interrupt paths. These establish the specific fix behaviors and remaining acceptance defects without executing protocol scenarios. Marshal clippy/tests and the full Rust differential procedure were not rerun by these reviewers; the author's reported 183-second protocol result is not independently recertified.

The auditors found no additional substantiated critical/high issue. A stubbed validator failure after printing a valid first line demonstrated a general output/status limitation, but no corresponding internal exception path in the current validator was established; it is not promoted to another confirmed finding.

**Snapshot identifiers**

The [44-file manifest](/private/tmp/tss-differential-review-uqd42fk3/manifest.json) pins the reviewed inputs and records no change during copying. The only later source change observed was the visibility of `RecordingResolver::holding`, retained in [the follow-up record](/private/tmp/tss-differential-review-uqd42fk3/follow-up.json). Finding inputs remain unchanged. References use symbols and sections, without unpinned source line numbers.

| File | SHA-256 |
| --- | --- |
| `statelens/scripts/differential.sh` | `67f5843851d6f128ff00e692cc925b5054cd89ec0b9590a76d119d91b05b28e1` |
| `statelens/scripts/statelens.py` | `24efb7824a0526084414c33431bafb3fbd7697697b726f964a74ba7de185694f` |
| `statelens/scripts/test_statelens.py` | `76b097c774867c35e02367344f9c8494fff3067dde37696abacec9fce3793f2a` |
| `statelens/differential/src/tests.rs` | `a13ca95f3774831138ce152788eaccec3f9b57244a073fe695618b01f4aec233` |
| `statelens/differential/src/digest.rs` | `3648dcf960236e88b62ab4bcb2b63ecce82666bafe983d9a7dfad5eed85f70fc` |
| `statelens/differential/src/cards/ts9005.rs` | `1ab362f9eaf6930e3a4a7499bb4d2aeb2437d77be1665f58c784cdcc2b89889b` |
| `statelens/differential/src/cards/ts9006.rs` | `bc35acd40ac07cb7cd048479832ae9eb47d6fbadc4f13e3132191a8f9b283372` |
| `statelens/docs/SPEC.md` | `0e6e3100c6abe80aeeef3d073ff69eceebbef7561481637a1f50e84fde716970` |

The [fix-verification 44-file manifest](/private/tmp/tss-diff-fix-review-9pn2fpgw/manifest.json) pins the later tree against the same HEAD. The table above belongs to the original review. Current changed inputs include:

| File | SHA-256 at fix verification |
| --- | --- |
| `statelens/scripts/differential.sh` | `773b97160e4062e7deb2f96d6fd1dff92584d119bcc7320263ec1acc5ce42626` |
| `statelens/differential/src/cards/ts9005.rs` | `f53f94a19d227ede75b536b367c15996e322847db1b4c46b4bc468cc09f3fc4d` |
| `statelens/differential/src/cards/ts9006.rs` | `fe04aa5ccf81ef4c3cb786109103b8927137aa50c1c45bbb2bdb003c99d9cc04` |
| `statelens/docs/SPEC.md` | `40fff4a0359b9945699ebdb9316e759a928ba58e42582310793c67b2bd415a93` |

The validator, its Python tests, the digest and the Rust test inventory retain their original-review hashes. At completion, all 43 non-report files in the fix-verification manifest still match, and HEAD is unchanged. Source references use paths, symbols and sections; no unpinned source line numbers were added.
