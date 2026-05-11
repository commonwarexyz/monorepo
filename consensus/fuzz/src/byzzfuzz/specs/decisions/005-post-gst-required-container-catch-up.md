# ADR-005: Post-GST Required-Container Catch-Up

## Status

Accepted

## Context

A pure safety-oriented fuzz run can miss schedules where the protocol stops making progress after a bounded fault window.
ByzzFuzz also needs to check liveness property: network faults stop after GST, but the byzantine process can keep omitting
targeted deliveries and equivocating through semantically mutated, re-signed votes.

ADR-003 required every non-byzantine reporter to finalize above its baseline within the post-GST window. That proved fresh
post-GST progress, but it did not require reporters that missed `required_containers` before GST to catch up to
`required_containers` after GST.

## Decision

Run a bounded fault phase first. If every non-byzantine reporter reaches `required_containers`
from the input of this fuzz iteration, skip GST and go directly to safety checks using the invariants.
Otherwise, record each non-byzantine reporter's baseline (its last finalized view),
reach GST by opening `FaultGate`, prune dormant pre-GST process faults above the byzantine round,
append fresh post-GST process faults for views beyond the byzantine's pre-GST round, and require
every non-byzantine reporter to reach its post-GST target within the post-GST window. Dormant
pre-GST faults at strictly higher views are pruned to prevent double-fire; faults at exactly
`byzantine_rnd` are retained because the cell can equal that view via inbound receipt before the
byzantine has emitted every outbound message for it.

The target is computed per reporter:

- If `baseline < required_containers`, the target is `required_containers`.
- If `baseline >= required_containers`, the target is `baseline + 1`.

Reporters that reach `required_containers` between the Phase 1 exit and the Phase 2 baseline
capture have `baseline == required_containers` and therefore a target of
`required_containers + 1`. This stricter post-boundary requirement is intentional: Phase 2 must
observe fresh progress.

Detailed liveness logic, moved from `consensus/fuzz/src/byzzfuzz/runner.rs`:

```text
Run a single ByzzFuzz iteration. Designed around a liveness check so
the harness panics on both safety violations and stalled progress.

Phase 1 applies network partition faults until either every non-byzantine
reporter reaches `required_containers` or the fault phase elapses. Phase 2
reaches GST on the shared gate. A reporter below `required_containers` at
GST must reach `required_containers`; a reporter already at or above
`required_containers` must finalize at least one view above its pre-GST
baseline. If either target is missed within the post-GST window, the
runner panics. Byzantine process faults may fire in either phase. At GST
the runner prunes any dormant pre-GST faults at views the byzantine has
not yet reached, then appends fresh faults for `[byzantine_rnd + 1,
byzantine_rnd + r_post_gst]` so the appended post-GST views never
double-fire and Phase 2 keeps the post-GST adversary schedulable (the
appended faults still only fire when the byzantine emits matching
outbound messages at those views).

time
  |------ Phase 1: fault phase -------|---- Phase 2: post-GST window -----|
  | network partitions may drop msgs  | all network links deliver msgs    |
  | Byzantine process faults may run  | Byzantine process faults may run  |
  |                                   |                                   |
  | phase timer elapses               | correct reporters below target    |
  |                                   | must reach required_containers    |
  |                                   | (otherwise advance above baseline)|
  |                                   |                                   |
  +-----------------------------------+-----------------------------------+
                                      |
                                      +-- record finalization baselines,
                                          then reach GST

  (alternative) Phase 1 early completion: every non-byzantine reporter
  reaches `required_containers` before the phase timer elapses. The run
  skips GST and Phase 2, going straight to safety invariants.

If all non-byzantine reporters reach `required_containers` during Phase 1,
the run skips the post-GST check and proceeds directly to safety invariants.
```

## Consequences

The harness checks both safety and liveness in successful ByzzFuzz runs.
Network partitions stop at GST, but the Byzantine sender is still adversarial after GST and can equivocate with mutated votes or omit targeted deliveries.
The post-GST timeout must be calibrated conservatively to avoid false liveness failures from honest retry and recovery timers.
Current code uses a large virtual-time window.

The liveness oracle is stricter than ADR-003. A reporter that misses `required_containers` during Phase 1 must catch up to
`required_containers` after GST, not merely finalize one additional container.

## Alternatives Considered

- Keep ADR-003's one-container post-GST progress rule for all reporters. Rejected because it can pass when Phase 1 ended far below `required_containers`.
- Always require `required_containers + 1` after GST. Rejected because reporters below the target should first be judged against the fuzz input's target, while reporters already at or above it need fresh progress relative to their own baseline.
- Disable all faults at GST. Rejected because it would stop testing Byzantine process behavior during the recovery period.
- Run only safety checks. Rejected because stalled progress is a core failure mode for BFT protocols under eventual synchrony.
